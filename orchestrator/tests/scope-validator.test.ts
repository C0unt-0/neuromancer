import { describe, it, expect } from "vitest";
import { ScopeValidator } from "../src/scope/scope-validator.js";

describe("ScopeValidator", () => {
  const validator = new ScopeValidator({
    allowedCidrs: ["10.10.11.0/24", "192.168.1.0/24"],
    blockedCidrs: ["127.0.0.0/8", "169.254.0.0/16"],
  });

  it("allows IP within scope", async () => {
    const result = await validator.validate("10.10.11.234");
    expect(result.allowed).toBe(true);
    expect(result.matchedCidr).toBe("10.10.11.0/24");
  });

  it("rejects IP outside scope", async () => {
    const result = await validator.validate("8.8.8.8");
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("not within any allowed CIDR");
  });

  it("rejects blocked IPs even if in scope range", async () => {
    const v = new ScopeValidator({
      allowedCidrs: ["127.0.0.0/8"],
      blockedCidrs: ["127.0.0.0/8"],
    });
    const result = await v.validate("127.0.0.1");
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain("blocked");
  });

  it("validates CIDR boundary correctly", async () => {
    const result1 = await validator.validate("10.10.11.0");
    expect(result1.allowed).toBe(true);
    const result2 = await validator.validate("10.10.11.255");
    expect(result2.allowed).toBe(true);
    const result3 = await validator.validate("10.10.12.1");
    expect(result3.allowed).toBe(false);
  });
});
