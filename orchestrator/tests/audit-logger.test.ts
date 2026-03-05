import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { AuditLogger } from "../src/scope/audit-logger.js";
import { existsSync, unlinkSync } from "fs";
import { readFile, writeFile, appendFile } from "fs/promises";
import { createHash } from "crypto";

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

  // --- C2: Hash chain corruption on write failure ---

  describe("C2: hash chain resilience on write failure", () => {
    it("does not corrupt lastHash when appendFile fails", async () => {
      const FAIL_LOG = "/tmp/cyberdeck-test-failwrite.jsonl";
      // Clean up from any previous run
      if (existsSync(FAIL_LOG)) unlinkSync(FAIL_LOG);

      const failLogger = new AuditLogger(FAIL_LOG);

      // Write one good entry
      await failLogger.log({ sessionId: "s1", action: "first" });

      // Read what we wrote so we can verify the chain later
      const contentBefore = await readFile(FAIL_LOG, "utf-8");
      const linesBefore = contentBefore.trim().split("\n").filter(Boolean);
      expect(linesBefore.length).toBe(1);

      // Now make the path unwritable by replacing the file with a directory
      unlinkSync(FAIL_LOG);
      const { mkdirSync, rmdirSync } = await import("fs");
      mkdirSync(FAIL_LOG);

      // This log call should fail (can't append to a directory)
      let failed = false;
      try {
        await failLogger.log({ sessionId: "s1", action: "failing_write" });
      } catch {
        failed = true;
      }
      expect(failed).toBe(true);

      // Restore: remove directory, recreate file with original content
      rmdirSync(FAIL_LOG);
      await writeFile(FAIL_LOG, contentBefore);

      // Write another entry — the chain should still be valid because
      // lastHash was NOT advanced on the failed write
      await failLogger.log({ sessionId: "s1", action: "after_failure" });

      const verifier = new AuditLogger(FAIL_LOG);
      const result = await verifier.verify();
      expect(result.valid).toBe(true);

      // Clean up
      unlinkSync(FAIL_LOG);
    });
  });

  describe("C2: init() resumes hash chain from existing file", () => {
    it("resumes hash chain when instantiated against existing log", async () => {
      // Write entries with first logger
      const logger1 = new AuditLogger(TEST_LOG);
      await logger1.log({ sessionId: "s1", action: "entry_one" });
      await logger1.log({ sessionId: "s1", action: "entry_two" });

      // Create new logger against same file and call init()
      const logger2 = new AuditLogger(TEST_LOG);
      await logger2.init();
      await logger2.log({ sessionId: "s1", action: "entry_three" });

      // The full chain should verify
      const verifier = new AuditLogger(TEST_LOG);
      const result = await verifier.verify();
      expect(result.valid).toBe(true);
    });

    it("init() with nonexistent file keeps GENESIS", async () => {
      const FRESH_LOG = "/tmp/cyberdeck-test-fresh-init.jsonl";
      // Clean up from any previous run
      if (existsSync(FRESH_LOG)) unlinkSync(FRESH_LOG);

      const freshLogger = new AuditLogger(FRESH_LOG);
      await freshLogger.init();
      await freshLogger.log({ sessionId: "s1", action: "first" });

      const content = await readFile(FRESH_LOG, "utf-8");
      const firstLine = content.trim().split("\n")[0];
      const entry = JSON.parse(firstLine);
      expect(entry.prevHash).toBe("GENESIS");

      // Clean up
      unlinkSync(FRESH_LOG);
    });
  });

  // --- C7: JSON.parse unguarded ---

  describe("C7: corrupted lines handling", () => {
    it("verify() returns valid:false with reason on corrupted line", async () => {
      // Write valid entries
      await logger.log({ sessionId: "s1", action: "good_entry" });

      // Append a corrupted line
      await appendFile(TEST_LOG, "THIS IS NOT VALID JSON\n");

      // Write another valid line (won't link properly but the corrupted line should be caught first)
      const result = await logger.verify();
      expect(result.valid).toBe(false);
      expect(result.brokenAt).toBe(1);
      expect(result.reason).toBe("corrupted");
    });

    it("verify() does not throw on corrupted line", async () => {
      await appendFile(TEST_LOG, "NOT JSON\n");

      // Should NOT throw, should return a structured error
      const result = await logger.verify();
      expect(result.valid).toBe(false);
      expect(result.brokenAt).toBe(0);
      expect(result.reason).toBe("corrupted");
    });

    it("export() skips corrupted lines instead of throwing", async () => {
      await logger.log({ sessionId: "s1", action: "good_one" });
      await appendFile(TEST_LOG, "CORRUPTED LINE\n");
      await logger.log({ sessionId: "s1", action: "good_two" });

      // Should NOT throw, should skip the corrupted line
      const entries = await logger.export("2020-01-01", "2030-01-01");
      expect(entries.length).toBe(2);
      expect(entries[0].action).toBe("good_one");
      expect(entries[1].action).toBe("good_two");
    });
  });

  // --- I10: Tampering detection ---

  describe("I10: tampering detection", () => {
    it("detects modified log entry", async () => {
      await logger.log({ sessionId: "s1", action: "entry_one" });
      await logger.log({ sessionId: "s1", action: "entry_two" });
      await logger.log({ sessionId: "s1", action: "entry_three" });

      // Tamper with the second entry
      const content = await readFile(TEST_LOG, "utf-8");
      const lines = content.trim().split("\n");
      const entry = JSON.parse(lines[1]);
      entry.action = "TAMPERED";
      lines[1] = JSON.stringify(entry);
      await writeFile(TEST_LOG, lines.join("\n") + "\n");

      const result = await logger.verify();
      expect(result.valid).toBe(false);
      // The tampered line itself will have correct prevHash, but the NEXT line
      // will have a prevHash that doesn't match the hash of the tampered line.
      // Actually: modifying the content changes the hash of line[1], so line[2]'s
      // prevHash won't match. brokenAt should be 2.
      expect(result.brokenAt).toBe(2);
    });

    it("detects deleted log entry", async () => {
      await logger.log({ sessionId: "s1", action: "entry_one" });
      await logger.log({ sessionId: "s1", action: "entry_two" });
      await logger.log({ sessionId: "s1", action: "entry_three" });

      // Delete the second entry
      const content = await readFile(TEST_LOG, "utf-8");
      const lines = content.trim().split("\n");
      lines.splice(1, 1); // remove line at index 1
      await writeFile(TEST_LOG, lines.join("\n") + "\n");

      const result = await logger.verify();
      expect(result.valid).toBe(false);
      // After deleting line[1], the old line[2] (now line[1]) has a prevHash
      // that points to the hash of the deleted line, not line[0].
      expect(result.brokenAt).toBe(1);
    });
  });

  // --- I11: Concurrent log() calls ---

  describe("I11: concurrent log() serialization", () => {
    it("maintains valid hash chain under concurrent writes", async () => {
      // Fire off many concurrent log calls
      const promises = [];
      for (let i = 0; i < 20; i++) {
        promises.push(
          logger.log({ sessionId: "s1", action: `concurrent_${i}` })
        );
      }
      await Promise.all(promises);

      // All 20 entries should be present
      const entries = await logger.export("2020-01-01", "2030-01-01");
      expect(entries.length).toBe(20);

      // The hash chain should be fully valid
      const result = await logger.verify();
      expect(result.valid).toBe(true);
    });
  });
});
