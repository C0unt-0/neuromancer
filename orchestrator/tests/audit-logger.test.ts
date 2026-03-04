import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { AuditLogger } from "../src/scope/audit-logger.js";
import { existsSync, unlinkSync } from "fs";

const TEST_LOG = "/tmp/cyberdeck-test-audit.jsonl";

describe("AuditLogger", () => {
  let logger: AuditLogger;

  beforeEach(() => {
    logger = new AuditLogger(TEST_LOG);
  });

  afterEach(() => {
    if (existsSync(TEST_LOG)) unlinkSync(TEST_LOG);
  });

  it("writes entries to JSONL file", async () => {
    await logger.log({
      sessionId: "test-session",
      action: "tool_execute",
      tool: "nmap-scan",
      target: "10.10.11.234",
    });

    const entries = await logger.export("2020-01-01", "2030-01-01");
    expect(entries.length).toBe(1);
    expect(entries[0].action).toBe("tool_execute");
    expect(entries[0].tool).toBe("nmap-scan");
  });

  it("maintains hash chain integrity", async () => {
    await logger.log({ sessionId: "s1", action: "session_start" });
    await logger.log({ sessionId: "s1", action: "tool_execute", tool: "nmap-scan" });
    await logger.log({ sessionId: "s1", action: "session_end" });

    const result = await logger.verify();
    expect(result.valid).toBe(true);
  });

  it("includes timestamp and id", async () => {
    await logger.log({ sessionId: "s1", action: "scope_check" });

    const entries = await logger.export("2020-01-01", "2030-01-01");
    expect(entries[0].id).toBeDefined();
    expect(entries[0].timestamp).toBeDefined();
    expect(entries[0].prevHash).toBeDefined();
  });
});
