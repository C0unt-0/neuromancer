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

  constructor(logPath: string) {
    this.logPath = logPath;
  }

  async log(entry: Omit<AuditEntry, "id" | "timestamp" | "prevHash">): Promise<void> {
    const full: AuditEntry = {
      ...entry,
      id: nanoid(),
      timestamp: new Date().toISOString(),
      prevHash: this.lastHash,
    };

    const line = JSON.stringify(full);
    this.lastHash = createHash("sha256").update(line).digest("hex");

    await appendFile(this.logPath, line + "\n");
  }

  async verify(): Promise<{ valid: boolean; brokenAt?: number }> {
    if (!existsSync(this.logPath)) return { valid: true };

    const content = await readFile(this.logPath, "utf-8");
    const lines = content.trim().split("\n").filter(Boolean);

    let expectedPrevHash = "GENESIS";
    for (let i = 0; i < lines.length; i++) {
      const entry: AuditEntry = JSON.parse(lines[i]);
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

    return lines
      .map((line) => JSON.parse(line) as AuditEntry)
      .filter((entry) => {
        const ts = new Date(entry.timestamp).getTime();
        return ts >= new Date(startDate).getTime() && ts <= new Date(endDate).getTime();
      });
  }
}
