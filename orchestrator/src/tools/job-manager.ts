import { EventEmitter } from "events";
import { CONFIG } from "../config.js";
import { ToolRunner, type ToolJob } from "./tool-runner.js";
import { ScopeValidator } from "../scope/scope-validator.js";
import { AuditLogger } from "../scope/audit-logger.js";
import { TOOLS } from "./tool-registry.js";
import { parseToolOutput, type ToolResult } from "./result-parser.js";

export interface JobManagerEvents {
  "job:started": (job: ToolJob) => void;
  "job:output": (jobId: string, chunk: string, stream: "stdout" | "stderr") => void;
  "job:structured": (jobId: string, result: ToolResult) => void;
  "job:completed": (job: ToolJob) => void;
  "job:error": (jobId: string, error: string) => void;
  "job:queued": (job: ToolJob) => void;
}

interface QueuedJob {
  toolId: string;
  params: Record<string, unknown>;
  allowedCidrs: string[];
  sessionId: string;
}

export class JobManager extends EventEmitter {
  private runner: ToolRunner;
  private scopeValidator: ScopeValidator;
  private auditLogger: AuditLogger;
  private queue: QueuedJob[] = [];
  private recentJobTimestamps: number[] = [];

  constructor(
    scopeValidator: ScopeValidator,
    auditLogger: AuditLogger
  ) {
    super();
    this.runner = new ToolRunner();
    this.scopeValidator = scopeValidator;
    this.auditLogger = auditLogger;

    // Forward runner events
    this.runner.on("job:started", (job: ToolJob) => this.emit("job:started", job));
    this.runner.on("job:output", (jobId: string, chunk: string, stream: "stdout" | "stderr") =>
      this.emit("job:output", jobId, chunk, stream)
    );
    this.runner.on("job:completed", (job: ToolJob) => {
      this.onJobCompleted(job);
      this.processQueue();
    });
    this.runner.on("job:error", (jobId: string, error: string) => {
      this.emit("job:error", jobId, error);
      this.processQueue();
    });
  }

  async submitJob(
    toolId: string,
    params: Record<string, unknown>,
    allowedCidrs: string[],
    sessionId: string
  ): Promise<{ jobId?: string; error?: string; queued?: boolean }> {
    const tool = TOOLS[toolId];
    if (!tool) return { error: `Unknown tool: ${toolId}` };

    // Check tool risk level against scope restrictions
    if (!this.scopeValidator.isToolAllowed(tool.riskLevel)) {
      await this.auditLogger.log({
        sessionId,
        action: "tool_blocked",
        tool: toolId,
        target: params.target as string,
        scopeResult: "denied",
        details: `Risk level '${tool.riskLevel}' not permitted by scope restrictions`,
      });
      return { error: `Tool risk level '${tool.riskLevel}' not permitted by scope restrictions` };
    }

    // Validate target scope
    if (tool.requiresScope && params.target) {
      const target = String(params.target);
      // Extract IP/hostname from URL if needed
      const ip = extractHost(target);
      const result = await this.scopeValidator.validate(ip);
      if (!result.allowed) {
        await this.auditLogger.log({
          sessionId,
          action: "scope_denied",
          tool: toolId,
          target: ip,
          scopeResult: "denied",
          details: result.reason,
        });
        return { error: result.reason };
      }
    }

    // Check rate limit
    if (!this.checkRateLimit()) {
      // Queue the job
      this.queue.push({ toolId, params, allowedCidrs, sessionId });
      const queuedJob = this.runner.createJob(toolId, params);
      this.emit("job:queued", queuedJob);
      return { jobId: queuedJob.id, queued: true };
    }

    // Check concurrency limit
    if (this.runner.getActiveJobCount() >= CONFIG.MAX_CONCURRENT_TOOLS) {
      this.queue.push({ toolId, params, allowedCidrs, sessionId });
      const queuedJob = this.runner.createJob(toolId, params);
      this.emit("job:queued", queuedJob);
      return { jobId: queuedJob.id, queued: true };
    }

    // Execute immediately
    await this.auditLogger.log({
      sessionId,
      action: "tool_execute",
      tool: toolId,
      target: params.target as string,
      params,
      scopeResult: "allowed",
    });

    this.recentJobTimestamps.push(Date.now());
    const jobId = await this.runner.runTool(toolId, params, allowedCidrs);
    return { jobId };
  }

  async cancelJob(jobId: string): Promise<void> {
    await this.runner.cancelJob(jobId);
  }

  getJob(jobId: string): ToolJob | undefined {
    return this.runner.getJob(jobId);
  }

  listJobs(): ToolJob[] {
    return this.runner.listJobs();
  }

  getQueueLength(): number {
    return this.queue.length;
  }

  private checkRateLimit(): boolean {
    const now = Date.now();
    const windowStart = now - 60_000; // 1 minute window
    this.recentJobTimestamps = this.recentJobTimestamps.filter((t) => t > windowStart);
    return this.recentJobTimestamps.length < CONFIG.MAX_JOBS_PER_MINUTE;
  }

  private async processQueue(): Promise<void> {
    if (this.queue.length === 0) return;
    if (this.runner.getActiveJobCount() >= CONFIG.MAX_CONCURRENT_TOOLS) return;
    if (!this.checkRateLimit()) return;

    const next = this.queue.shift();
    if (!next) return;

    this.recentJobTimestamps.push(Date.now());

    await this.auditLogger.log({
      sessionId: next.sessionId,
      action: "tool_execute",
      tool: next.toolId,
      target: next.params.target as string,
      params: next.params,
      scopeResult: "allowed",
      details: "dequeued",
    });

    await this.runner.runTool(next.toolId, next.params, next.allowedCidrs);
  }

  private onJobCompleted(job: ToolJob): void {
    // Parse structured results from raw output
    const tool = TOOLS[job.toolId];
    if (tool?.outputParser && tool.outputParser !== "plain" && job.rawOutput) {
      try {
        const result = parseToolOutput(job.toolId, job.rawOutput, job.targetIp);
        job.structuredResults = result;
        this.emit("job:structured", job.id, result);
      } catch {
        // Parsing failure is non-fatal — raw output is still available
      }
    }

    this.emit("job:completed", job);

    this.auditLogger.log({
      sessionId: "system",
      action: "tool_completed",
      tool: job.toolId,
      target: job.targetIp,
      result: job.status === "completed" ? "success" : "failure",
      details: `Exit code: ${job.exitCode}, Duration: ${(job.completedAt ?? 0) - (job.startedAt ?? 0)}ms`,
    }).catch(() => {});
  }
}

function extractHost(target: string): string {
  try {
    const url = new URL(target);
    return url.hostname;
  } catch {
    return target;
  }
}
