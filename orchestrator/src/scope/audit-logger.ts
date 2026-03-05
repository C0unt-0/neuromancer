import { appendFile, readFile } from "fs/promises";
import { existsSync } from "fs";
import { createHash } from "crypto";
import { nanoid } from "nanoid";

export interface AuditEntry {
  id: string;
  timestamp: string;
  sessionId: string;
  action: string;
  tool?: string;
  target?: string;
  params?: Record<string, unknown>;
  scopeResult?: "allowed" | "denied";
  result?: "success" | "failure" | "timeout" | "cancelled";
  details?: string;
  prevHash: string;
}

export class AuditLogger {
  private logPath: string;
  private lastHash: string = "GENESIS";
  private writeQueue: Promise<void> = Promise.resolve();

  constructor(logPath: string) {
    this.logPath = logPath;
  }

  /**
   * Initialize the logger from an existing log file, resuming the hash chain
   * from the last valid entry. If the file does not exist, keeps "GENESIS".
   */
  async init(): Promise<void> {
    if (!existsSync(this.logPath)) return;

    const content = await readFile(this.logPath, "utf-8");
    const lines = content.trim().split("\n").filter(Boolean);

    if (lines.length === 0) return;

    // Rebuild the hash chain by computing the hash of the last line
    const lastLine = lines[lines.length - 1];
    this.lastHash = createHash("sha256").update(lastLine).digest("hex");
  }

  async log(entry: Omit<AuditEntry, "id" | "timestamp" | "prevHash">): Promise<void> {
    const op = this.writeQueue.then(async () => {
      const full: AuditEntry = {
        ...entry,
        id: nanoid(),
        timestamp: new Date().toISOString(),
        prevHash: this.lastHash,
      };

      const line = JSON.stringify(full);
      const hash = createHash("sha256").update(line).digest("hex");

      // Write to file FIRST — only update lastHash on success
      await appendFile(this.logPath, line + "\n");
      this.lastHash = hash;
    });

    // Prevent unhandled rejection from breaking the queue chain,
    // but still propagate the error to the caller via `return op`
    this.writeQueue = op.catch(() => {});
    return op;
  }

  async verify(): Promise<{ valid: boolean; brokenAt?: number; reason?: string }> {
    if (!existsSync(this.logPath)) return { valid: true };

    const content = await readFile(this.logPath, "utf-8");
    const lines = content.trim().split("\n").filter(Boolean);

    let expectedPrevHash = "GENESIS";
    for (let i = 0; i < lines.length; i++) {
      let entry: AuditEntry;
      try {
        entry = JSON.parse(lines[i]);
      } catch {
        return { valid: false, brokenAt: i, reason: "corrupted" };
      }

      if (entry.prevHash !== expectedPrevHash) {
        return { valid: false, brokenAt: i };
      }
      expectedPrevHash = createHash("sha256").update(lines[i]).digest("hex");
    }

    return { valid: true };
  }

  async export(startDate: string, endDate: string): Promise<AuditEntry[]> {
    if (!existsSync(this.logPath)) return [];

    const content = await readFile(this.logPath, "utf-8");
    const lines = content.trim().split("\n").filter(Boolean);

    const startMs = new Date(startDate).getTime();
    const endMs = new Date(endDate).getTime();
    const results: AuditEntry[] = [];

    for (const line of lines) {
      let entry: AuditEntry;
      try {
        entry = JSON.parse(line) as AuditEntry;
      } catch {
        // Skip corrupted lines
        continue;
      }

      const ts = new Date(entry.timestamp).getTime();
      if (ts >= startMs && ts <= endMs) {
        results.push(entry);
      }
    }

    return results;
  }
}
