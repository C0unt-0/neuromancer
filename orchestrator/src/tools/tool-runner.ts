import Docker from "dockerode";
import { EventEmitter } from "events";
import { Writable } from "stream";
import { nanoid } from "nanoid";
import { CONFIG } from "../config.js";
import { TOOLS } from "./tool-registry.js";

export interface ToolJob {
  id: string;
  toolId: string;
  params: Record<string, unknown>;
  targetIp: string;
  status: "queued" | "running" | "completed" | "failed" | "cancelled" | "timeout";
  containerId?: string;
  startedAt?: number;
  completedAt?: number;
  exitCode?: number;
  rawOutput: string;
  structuredResults?: unknown;
  error?: string;
}

export interface ToolRunnerEvents {
  "job:started": (job: ToolJob) => void;
  "job:output": (jobId: string, chunk: string, stream: "stdout" | "stderr") => void;
  "job:structured": (jobId: string, result: unknown) => void;
  "job:completed": (job: ToolJob) => void;
  "job:error": (jobId: string, error: string) => void;
}

export class ToolRunner extends EventEmitter {
  private docker: Docker;
  private activeJobs: Map<string, ToolJob> = new Map();

  constructor() {
    super();
    this.docker = new Docker({ socketPath: CONFIG.DOCKER_SOCKET });
  }

  createJob(toolId: string, params: Record<string, unknown>): ToolJob {
    const job: ToolJob = {
      id: nanoid(),
      toolId,
      params,
      targetIp: (params.target as string) ?? "",
      status: "queued",
      rawOutput: "",
    };
    this.activeJobs.set(job.id, job);
    return job;
  }

  async runTool(
    toolId: string,
    params: Record<string, unknown>,
    allowedCidrs: string[] = []
  ): Promise<string> {
    const tool = TOOLS[toolId];
    if (!tool) throw new Error(`Unknown tool: ${toolId}`);

    // Validate params against tool schema
    const validated = tool.paramSchema.parse(params);
    const command = tool.buildCommand(validated);

    const job = this.createJob(toolId, validated);
    job.status = "running";
    job.startedAt = Date.now();

    this.emit("job:started", job);

    // Run async — don't block the caller
    this.executeInContainer(job, command, tool.capabilities, allowedCidrs).catch(
      (err) => {
        job.status = "failed";
        job.error = err instanceof Error ? err.message : String(err);
        job.completedAt = Date.now();
        this.emit("job:error", job.id, job.error);
      }
    );

    return job.id;
  }

  private async executeInContainer(
    job: ToolJob,
    command: string,
    capabilities: string[],
    allowedCidrs: string[]
  ): Promise<void> {
    const capAdd = capabilities.length > 0 ? capabilities : undefined;

    // Create container with resource limits and security constraints
    const container = await this.docker.createContainer({
      Image: CONFIG.TOOL_IMAGE,
      Cmd: ["sleep", "infinity"],
      User: "root", // Need root for iptables, then switch to operator
      HostConfig: {
        Memory: CONFIG.CONTAINER_MEMORY_LIMIT,
        NanoCpus: CONFIG.CONTAINER_CPU_LIMIT * 1e9,
        PidsLimit: CONFIG.CONTAINER_PIDS_LIMIT,
        AutoRemove: true,
        CapAdd: capAdd,
        CapDrop: ["ALL"],
        SecurityOpt: ["no-new-privileges"],
      },
    });

    job.containerId = container.id;

    try {
      await container.start();

      // Enforce scope via iptables inside the container
      if (allowedCidrs.length > 0) {
        const cidrArgs = allowedCidrs.join(" ");
        await this.containerExec(container, [
          "bash", "-c", `/usr/local/bin/iptables-scope.sh ${cidrArgs}`,
        ]);
      }

      // For custom scripts, write the script file first
      if (job.toolId === "custom-script" && job.params.script) {
        const ext = job.params.language === "python" ? "py" : "sh";
        const scriptContent = String(job.params.script);
        // Write script via heredoc to avoid shell injection
        await this.containerExec(container, [
          "bash", "-c",
          `cat > /tmp/script.${ext} << 'CYBERDECK_SCRIPT_EOF'\n${scriptContent}\nCYBERDECK_SCRIPT_EOF`,
        ]);
      }

      // Build command array to avoid shell injection — run as operator
      const cmdArray = ["su", "-c", command, "operator"];

      // Execute the actual tool
      const toolExec = await container.exec({
        Cmd: cmdArray,
        AttachStdout: true,
        AttachStderr: true,
      });

      const stream = await toolExec.start({ Detach: false, Tty: false });

      // Set up timeout
      const timeoutId = setTimeout(async () => {
        job.status = "timeout";
        job.completedAt = Date.now();
        try {
          await container.stop({ t: 2 });
        } catch {
          // Container may already be stopped
        }
        this.emit("job:error", job.id, "Tool execution timed out");
      }, CONFIG.CONTAINER_TIMEOUT_SEC * 1000);

      // Stream output via demuxStream using proper Writable streams
      const stdoutStream = new Writable({
        write: (chunk, _encoding, callback) => {
          const text = chunk.toString();
          job.rawOutput += text;
          this.emit("job:output", job.id, text, "stdout");
          callback();
        },
      });
      const stderrStream = new Writable({
        write: (chunk, _encoding, callback) => {
          const text = chunk.toString();
          job.rawOutput += text;
          this.emit("job:output", job.id, text, "stderr");
          callback();
        },
      });

      await new Promise<void>((resolve, reject) => {
        this.docker.modem.demuxStream(stream, stdoutStream, stderrStream);

        stream.on("end", resolve);
        stream.on("error", reject);
      });

      clearTimeout(timeoutId);

      // Get exit code
      const inspectResult = await toolExec.inspect();
      job.exitCode = inspectResult.ExitCode ?? undefined;

      if (job.status === "timeout" || job.status === "cancelled") return;

      job.status = job.exitCode === 0 ? "completed" : "failed";
      job.completedAt = Date.now();
      this.emit("job:completed", job);
    } finally {
      // Clean up container
      try {
        await container.stop({ t: 2 });
      } catch {
        // AutoRemove handles this, or container already stopped
      }
    }
  }

  private async containerExec(
    container: Docker.Container,
    cmd: string[]
  ): Promise<string> {
    const e = await container.exec({
      Cmd: cmd,
      AttachStdout: true,
      AttachStderr: true,
    });

    const stream = await e.start({ Detach: false, Tty: false });
    let output = "";

    const stdout = new Writable({
      write: (chunk, _encoding, cb) => { output += chunk.toString(); cb(); },
    });
    const stderr = new Writable({
      write: (chunk, _encoding, cb) => { output += chunk.toString(); cb(); },
    });

    return new Promise((resolve, reject) => {
      this.docker.modem.demuxStream(stream, stdout, stderr);
      stream.on("end", () => resolve(output));
      stream.on("error", reject);
    });
  }

  async cancelJob(jobId: string): Promise<void> {
    const job = this.activeJobs.get(jobId);
    if (!job || job.status !== "running") return;

    job.status = "cancelled";
    job.completedAt = Date.now();

    if (job.containerId) {
      try {
        const container = this.docker.getContainer(job.containerId);
        await container.stop({ t: 2 });
      } catch {
        // Container may already be gone
      }
    }

    this.emit("job:completed", job);
  }

  getJob(jobId: string): ToolJob | undefined {
    return this.activeJobs.get(jobId);
  }

  listJobs(): ToolJob[] {
    return Array.from(this.activeJobs.values());
  }

  getActiveJobCount(): number {
    return Array.from(this.activeJobs.values()).filter(
      (j) => j.status === "running"
    ).length;
  }
}
