import { describe, it, expect, vi, beforeEach } from "vitest";
import { JobManager } from "../src/tools/job-manager.js";
import { ScopeValidator } from "../src/scope/scope-validator.js";
import { AuditLogger } from "../src/scope/audit-logger.js";

// Mock Docker-dependent ToolRunner — submitJob will fail at Docker level
// but we can test the validation/scope/rate-limit logic

function createJobManager() {
  const scopeValidator = new ScopeValidator({
    allowedCidrs: ["10.10.11.0/24", "192.168.1.0/24"],
    blockedCidrs: ["127.0.0.0/8"],
    restrictions: {
      allowActiveScanning: true,
      allowExploitation: false,
      allowBruteForce: false,
    },
  });
  const auditLogger = new AuditLogger("/tmp/cyberdeck-test-audit-jm.jsonl");
  return new JobManager(scopeValidator, auditLogger);
}

describe("JobManager", () => {
  describe("scope validation", () => {
    it("rejects tools targeting out-of-scope IPs", async () => {
      const jm = createJobManager();
      const result = await jm.submitJob(
        "nmap-scan",
        { target: "8.8.8.8" },
        ["10.10.11.0/24"],
        "session-1"
      );
      expect(result.error).toBeDefined();
      expect(result.error).toContain("not within any allowed CIDR");
    });

    it("rejects tools targeting blocked IPs", async () => {
      const jm = createJobManager();
      const result = await jm.submitJob(
        "nmap-scan",
        { target: "127.0.0.1" },
        ["127.0.0.0/8"],
        "session-1"
      );
      expect(result.error).toBeDefined();
      expect(result.error).toContain("blocked");
    });

    it("allows passive tools without scope check", async () => {
      const jm = createJobManager();
      // whois-lookup has requiresScope: false and riskLevel: passive
      // Docker isn't running so it will fail at execution, but scope check should pass
      const result = await jm.submitJob(
        "whois-lookup",
        { target: "example.com" },
        [],
        "session-1"
      );
      // Should get a jobId (tool was accepted) or a Docker error, not a scope error
      expect(result.error).toBeUndefined();
      expect(result.jobId).toBeDefined();
    });
  });

  describe("risk level restrictions", () => {
    it("rejects invasive tools when exploitation is disabled", async () => {
      const jm = createJobManager();
      const result = await jm.submitJob(
        "custom-script",
        { script: "echo test", language: "bash" as const, target: "10.10.11.1" },
        ["10.10.11.0/24"],
        "session-1"
      );
      expect(result.error).toBeDefined();
      expect(result.error).toContain("not permitted");
    });
  });

  describe("unknown tools", () => {
    it("rejects unknown tool IDs", async () => {
      const jm = createJobManager();
      const result = await jm.submitJob(
        "nonexistent-tool",
        {},
        [],
        "session-1"
      );
      expect(result.error).toBe("Unknown tool: nonexistent-tool");
    });
  });

  describe("job listing", () => {
    it("lists all jobs", () => {
      const jm = createJobManager();
      expect(jm.listJobs()).toEqual([]);
    });

    it("reports queue length", () => {
      const jm = createJobManager();
      expect(jm.getQueueLength()).toBe(0);
    });
  });
});
