import { EventEmitter } from "events";
import * as pty from "node-pty";
import { nanoid } from "nanoid";

export interface PtySession {
  id: string;
  jobId: string;
  ptyProcess: pty.IPty;
  createdAt: number;
}

export interface PtyBridgeEvents {
  "pty:data": (sessionId: string, data: string) => void;
  "pty:exit": (sessionId: string, exitCode: number) => void;
}

export class PtyBridge extends EventEmitter {
  private sessions: Map<string, PtySession> = new Map();

  /**
   * Spawn a PTY process for a tool execution.
   * Used when the tool needs interactive terminal features (ANSI colors, progress bars).
   */
  spawn(
    jobId: string,
    command: string,
    args: string[] = [],
    options: { cols?: number; rows?: number; env?: Record<string, string> } = {}
  ): string {
    const sessionId = nanoid();

    const ptyProcess = pty.spawn(command, args, {
      name: "xterm-256color",
      cols: options.cols ?? 120,
      rows: options.rows ?? 40,
      cwd: "/home/operator",
      env: {
        ...process.env,
        TERM: "xterm-256color",
        ...options.env,
      },
    });

    const session: PtySession = {
      id: sessionId,
      jobId,
      ptyProcess,
      createdAt: Date.now(),
    };

    this.sessions.set(sessionId, session);

    ptyProcess.onData((data: string) => {
      this.emit("pty:data", sessionId, data);
    });

    ptyProcess.onExit(({ exitCode }: { exitCode: number }) => {
      this.emit("pty:exit", sessionId, exitCode);
      this.sessions.delete(sessionId);
    });

    return sessionId;
  }

  /**
   * Write input to a PTY session (e.g., user typing in the terminal).
   */
  write(sessionId: string, data: string): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.ptyProcess.write(data);
    }
  }

  /**
   * Resize a PTY session (when the browser terminal resizes).
   */
  resize(sessionId: string, cols: number, rows: number): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.ptyProcess.resize(cols, rows);
    }
  }

  /**
   * Kill a PTY session.
   */
  kill(sessionId: string): void {
    const session = this.sessions.get(sessionId);
    if (session) {
      session.ptyProcess.kill();
      this.sessions.delete(sessionId);
    }
  }

  /**
   * Kill all PTY sessions for a given job.
   */
  killByJob(jobId: string): void {
    for (const [id, session] of this.sessions) {
      if (session.jobId === jobId) {
        session.ptyProcess.kill();
        this.sessions.delete(id);
      }
    }
  }

  getSession(sessionId: string): PtySession | undefined {
    return this.sessions.get(sessionId);
  }

  getActiveCount(): number {
    return this.sessions.size;
  }
}
