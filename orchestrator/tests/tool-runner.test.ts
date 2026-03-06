import { describe, it, expect } from "vitest";
import { ToolRunner } from "../src/tools/tool-runner.js";

describe("ToolRunner", () => {
  it("creates a job with correct initial state", () => {
    const runner = new ToolRunner();
    const job = runner.createJob("nmap-scan", { target: "10.10.11.234" });

    expect(job.toolId).toBe("nmap-scan");
    expect(job.status).toBe("queued");
    expect(job.id).toBeDefined();
    expect(job.targetIp).toBe("10.10.11.234");
    expect(job.rawOutput).toBe("");
  });

  it("tracks active jobs", () => {
    const runner = new ToolRunner();
    const job = runner.createJob("nmap-scan", { target: "10.10.11.234" });

    expect(runner.getJob(job.id)).toBeDefined();
    expect(runner.listJobs().length).toBe(1);
  });

  it("returns undefined for unknown job ID", () => {
    const runner = new ToolRunner();
    expect(runner.getJob("nonexistent")).toBeUndefined();
  });

  it("tracks multiple jobs independently", () => {
    const runner = new ToolRunner();
    const job1 = runner.createJob("nmap-scan", { target: "10.10.11.1" });
    const job2 = runner.createJob("nuclei-scan", { target: "10.10.11.2" });

    expect(runner.listJobs().length).toBe(2);
    expect(runner.getJob(job1.id)?.toolId).toBe("nmap-scan");
    expect(runner.getJob(job2.id)?.toolId).toBe("nuclei-scan");
  });

  it("counts active jobs correctly", () => {
    const runner = new ToolRunner();
    runner.createJob("nmap-scan", { target: "10.10.11.1" });
    // createJob sets status to "queued", not "running"
    expect(runner.getActiveJobCount()).toBe(0);
  });
});
