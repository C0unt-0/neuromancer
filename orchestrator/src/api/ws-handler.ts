import type { WebSocket } from "@fastify/websocket";
import type { FastifyBaseLogger } from "fastify";
import { nanoid } from "nanoid";
import { JobManager } from "../tools/job-manager.js";
import { ScopeValidator } from "../scope/scope-validator.js";
import { listTools, TOOLS } from "../tools/tool-registry.js";
import type { ScopeConfig } from "../scope/scope-config.js";
import type { ToolJob } from "../tools/tool-runner.js";
import type { ToolResult } from "../tools/result-parser.js";

// --- Client → Orchestrator message types ---

interface ToolExecuteMsg {
  type: "tool.execute";
  requestId: string;
  payload: { toolId: string; params: Record<string, unknown> };
}

interface ToolCancelMsg {
  type: "tool.cancel";
  payload: { jobId: string };
}

interface ToolListMsg {
  type: "tool.list";
  requestId: string;
}

interface AIMessageMsg {
  type: "ai.message";
  requestId: string;
  payload: {
    text: string;
    graphContext: Record<string, unknown>;
  };
}

interface AIApproveMsg {
  type: "ai.approve";
  payload: { approvalId: string };
}

interface AIRejectMsg {
  type: "ai.reject";
  payload: { approvalId: string };
}

interface ScopeGetMsg {
  type: "scope.get";
  requestId: string;
}

interface ScopeValidateMsg {
  type: "scope.validate";
  requestId: string;
  payload: { target: string };
}

type ClientMessage =
  | ToolExecuteMsg
  | ToolCancelMsg
  | ToolListMsg
  | AIMessageMsg
  | AIApproveMsg
  | AIRejectMsg
  | ScopeGetMsg
  | ScopeValidateMsg;

// --- Dependencies ---

export interface WsHandlerDeps {
  jobManager: JobManager;
  scopeValidator: ScopeValidator;
  scopeConfig: ScopeConfig;
  logger: FastifyBaseLogger;
}

export class WsHandler {
  private deps: WsHandlerDeps;
  private clients: Set<WebSocket> = new Set();

  constructor(deps: WsHandlerDeps) {
    this.deps = deps;
    this.setupJobManagerEvents();
  }

  handleConnection(socket: WebSocket): void {
    const sessionId = nanoid();
    this.clients.add(socket);
    this.deps.logger.info(`Client connected (session: ${sessionId})`);

    socket.on("message", (raw: Buffer) => {
      try {
        const msg = JSON.parse(raw.toString()) as ClientMessage;
        this.routeMessage(socket, msg, sessionId);
      } catch (err) {
        this.send(socket, {
          type: "toast",
          payload: {
            level: "error",
            title: "Invalid message",
            body: "Failed to parse message as JSON",
          },
        });
      }
    });

    socket.on("close", () => {
      this.clients.delete(socket);
      this.deps.logger.info(`Client disconnected (session: ${sessionId})`);
    });
  }

  private routeMessage(
    socket: WebSocket,
    msg: ClientMessage,
    sessionId: string
  ): void {
    switch (msg.type) {
      case "tool.execute":
        this.handleToolExecute(socket, msg, sessionId);
        break;
      case "tool.cancel":
        this.handleToolCancel(msg);
        break;
      case "tool.list":
        this.handleToolList(socket, msg);
        break;
      case "ai.message":
        this.handleAIMessage(socket, msg, sessionId);
        break;
      case "ai.approve":
        this.handleAIApprove(msg);
        break;
      case "ai.reject":
        this.handleAIReject(msg);
        break;
      case "scope.get":
        this.handleScopeGet(socket, msg);
        break;
      case "scope.validate":
        this.handleScopeValidate(socket, msg);
        break;
      default:
        this.deps.logger.warn(`Unknown message type: ${(msg as { type: string }).type}`);
    }
  }

  private async handleToolExecute(
    socket: WebSocket,
    msg: ToolExecuteMsg,
    sessionId: string
  ): Promise<void> {
    const { toolId, params } = msg.payload;
    const allowedCidrs = this.deps.scopeConfig.allowedCidrs;

    const result = await this.deps.jobManager.submitJob(
      toolId,
      params,
      allowedCidrs,
      sessionId
    );

    if (result.error) {
      this.send(socket, {
        type: "tool.error",
        payload: { jobId: msg.requestId, error: result.error },
      });
      return;
    }

    if (result.queued) {
      this.send(socket, {
        type: "toast",
        payload: {
          level: "info",
          title: "Job queued",
          body: `${toolId} is queued (${this.deps.jobManager.getQueueLength()} in queue)`,
        },
      });
    }
  }

  private async handleToolCancel(msg: ToolCancelMsg): Promise<void> {
    await this.deps.jobManager.cancelJob(msg.payload.jobId);
  }

  private handleToolList(socket: WebSocket, msg: ToolListMsg): void {
    const tools = listTools().map((t) => ({
      id: t.id,
      name: t.name,
      description: t.description,
      category: t.category,
      icon: t.icon,
      color: t.color,
      riskLevel: t.riskLevel,
      estimatedDurationSec: t.estimatedDurationSec,
    }));

    const jobs = this.deps.jobManager.listJobs().map((j) => ({
      id: j.id,
      toolId: j.toolId,
      target: j.targetIp,
      status: j.status,
      startedAt: j.startedAt,
    }));

    this.send(socket, {
      type: "tool.list",
      requestId: msg.requestId,
      payload: { tools, jobs },
    });
  }

  private handleAIMessage(
    socket: WebSocket,
    msg: AIMessageMsg,
    _sessionId: string
  ): void {
    // AI integration is a Week 5 task — stub for now
    this.send(socket, {
      type: "ai.chunk",
      payload: {
        sessionId: _sessionId,
        chunk: {
          type: "text",
          text: "AI operator is not yet connected. This will be implemented in Phase 1 Week 5.",
        },
      },
    });
    this.send(socket, {
      type: "ai.complete",
      payload: { sessionId: _sessionId },
    });
  }

  private handleAIApprove(_msg: AIApproveMsg): void {
    // AI approval gate — Week 5 stub
    this.deps.logger.info("AI approval received (not yet implemented)");
  }

  private handleAIReject(_msg: AIRejectMsg): void {
    // AI rejection gate — Week 5 stub
    this.deps.logger.info("AI rejection received (not yet implemented)");
  }

  private handleScopeGet(socket: WebSocket, msg: ScopeGetMsg): void {
    this.send(socket, {
      type: "scope.config",
      requestId: msg.requestId,
      payload: this.deps.scopeConfig,
    });
  }

  private async handleScopeValidate(
    socket: WebSocket,
    msg: ScopeValidateMsg
  ): Promise<void> {
    const result = await this.deps.scopeValidator.validate(msg.payload.target);
    this.send(socket, {
      type: "scope.validate.result",
      requestId: msg.requestId,
      payload: result,
    });
  }

  // --- Event forwarding: JobManager → all clients ---

  private setupJobManagerEvents(): void {
    this.deps.jobManager.on("job:started", (job: ToolJob) => {
      const tool = TOOLS[job.toolId];
      this.broadcast({
        type: "tool.started",
        payload: {
          jobId: job.id,
          toolId: job.toolId,
          target: job.targetIp,
          command: tool?.command ?? job.toolId,
          estimatedDuration: tool?.estimatedDurationSec ?? 30,
        },
      });
    });

    this.deps.jobManager.on(
      "job:output",
      (jobId: string, chunk: string, stream: "stdout" | "stderr") => {
        this.broadcast({
          type: "tool.output",
          payload: { jobId, chunk, stream },
        });
      }
    );

    this.deps.jobManager.on("job:structured", (jobId: string, result: ToolResult) => {
      this.broadcast({
        type: "tool.structured",
        payload: {
          jobId,
          toolId: result.toolId,
          targetIp: result.targetIp,
          discoveries: result.discoveries,
        },
      });
    });

    this.deps.jobManager.on("job:completed", (job: ToolJob) => {
      const durationSec = job.startedAt && job.completedAt
        ? (job.completedAt - job.startedAt) / 1000
        : 0;
      const discoveryCount =
        (job.structuredResults as { discoveries?: unknown[] })?.discoveries?.length ?? 0;

      this.broadcast({
        type: "tool.completed",
        payload: {
          jobId: job.id,
          exitCode: job.exitCode ?? -1,
          durationSec,
          discoveryCount,
        },
      });
    });

    this.deps.jobManager.on("job:error", (jobId: string, error: string) => {
      this.broadcast({
        type: "tool.error",
        payload: { jobId, error },
      });
    });
  }

  // --- Helpers ---

  private send(socket: WebSocket, msg: Record<string, unknown>): void {
    if (socket.readyState === 1) {
      socket.send(JSON.stringify(msg));
    }
  }

  private broadcast(msg: Record<string, unknown>): void {
    const data = JSON.stringify(msg);
    for (const client of this.clients) {
      if (client.readyState === 1) {
        client.send(data);
      }
    }
  }
}
