import { describe, it, expect } from "vitest";
import {
  TOOLS,
  getTool,
  listTools,
  getToolsByCategory,
} from "../src/tools/tool-registry.js";

describe("Tool Registry", () => {
  it("contains all 7 tools", () => {
    expect(Object.keys(TOOLS).length).toBe(7);
    expect(TOOLS["nmap-scan"]).toBeDefined();
    expect(TOOLS["nuclei-scan"]).toBeDefined();
    expect(TOOLS["gobuster-dir"]).toBeDefined();
    expect(TOOLS["whois-lookup"]).toBeDefined();
    expect(TOOLS["dig-dns"]).toBeDefined();
    expect(TOOLS["traceroute"]).toBeDefined();
    expect(TOOLS["custom-script"]).toBeDefined();
  });

  it("getTool returns correct tool", () => {
    const nmap = getTool("nmap-scan");
    expect(nmap).toBeDefined();
    expect(nmap!.name).toBe("Port Scan (nmap)");
    expect(nmap!.riskLevel).toBe("active");
  });

  it("getTool returns undefined for unknown tool", () => {
    expect(getTool("nonexistent")).toBeUndefined();
  });

  it("listTools returns all tools", () => {
    const tools = listTools();
    expect(tools.length).toBe(7);
  });

  it("getToolsByCategory filters correctly", () => {
    const recon = getToolsByCategory("recon");
    expect(recon.length).toBeGreaterThanOrEqual(3); // nmap, dig, traceroute, custom-script
    expect(recon.every((t) => t.category === "recon")).toBe(true);
  });

  describe("buildCommand", () => {
    it("builds nmap command with defaults", () => {
      const cmd = TOOLS["nmap-scan"].buildCommand({
        target: "10.10.11.234",
        ports: "-",
        flags: "-sV -sC -T4",
      });
      expect(cmd).toContain("nmap");
      expect(cmd).toContain("-sV -sC -T4");
      expect(cmd).toContain("10.10.11.234");
      expect(cmd).toContain("-oX -");
    });

    it("builds nmap command with scripts", () => {
      const cmd = TOOLS["nmap-scan"].buildCommand({
        target: "10.10.11.234",
        ports: "80,443",
        flags: "-sV",
        scripts: "vuln",
      });
      expect(cmd).toContain("--script=vuln");
      expect(cmd).toContain("-p 80,443");
    });

    it("builds nuclei command", () => {
      const cmd = TOOLS["nuclei-scan"].buildCommand({
        target: "http://10.10.11.234",
        severity: "critical,high",
      });
      expect(cmd).toContain("nuclei");
      expect(cmd).toContain("-target http://10.10.11.234");
      expect(cmd).toContain("-severity critical,high");
      expect(cmd).toContain("-jsonl");
    });

    it("builds whois command", () => {
      const cmd = TOOLS["whois-lookup"].buildCommand({ target: "example.com" });
      expect(cmd).toBe("whois example.com");
    });

    it("builds dig command with record type", () => {
      const cmd = TOOLS["dig-dns"].buildCommand({
        target: "example.com",
        recordType: "MX",
      });
      expect(cmd).toContain("dig example.com MX");
    });

    it("builds custom script command for python", () => {
      const cmd = TOOLS["custom-script"].buildCommand({
        script: "print('test')",
        language: "python",
      });
      expect(cmd).toContain("python3 /tmp/script.py");
    });

    it("builds custom script command for bash", () => {
      const cmd = TOOLS["custom-script"].buildCommand({
        script: "echo test",
        language: "bash",
        args: "--verbose",
      });
      expect(cmd).toContain("bash /tmp/script.sh --verbose");
    });
  });

  describe("param validation", () => {
    it("validates nmap params", () => {
      const schema = TOOLS["nmap-scan"].paramSchema;
      const result = schema.safeParse({ target: "10.10.11.234" });
      expect(result.success).toBe(true);
    });

    it("rejects nmap without target", () => {
      const schema = TOOLS["nmap-scan"].paramSchema;
      const result = schema.safeParse({});
      expect(result.success).toBe(false);
    });

    it("validates gobuster requires URL target", () => {
      const schema = TOOLS["gobuster-dir"].paramSchema;
      const valid = schema.safeParse({ target: "http://10.10.11.234" });
      expect(valid.success).toBe(true);

      const invalid = schema.safeParse({ target: "not-a-url" });
      expect(invalid.success).toBe(false);
    });
  });

  describe("risk levels", () => {
    it("passive tools don't require scope", () => {
      expect(TOOLS["whois-lookup"].requiresScope).toBe(false);
      expect(TOOLS["dig-dns"].requiresScope).toBe(false);
    });

    it("active tools require scope", () => {
      expect(TOOLS["nmap-scan"].requiresScope).toBe(true);
      expect(TOOLS["nuclei-scan"].requiresScope).toBe(true);
    });

    it("custom-script is invasive", () => {
      expect(TOOLS["custom-script"].riskLevel).toBe("invasive");
    });
  });
});
