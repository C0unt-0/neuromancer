import { describe, it, expect } from "vitest";
import { ScopeValidator, ValidationResult } from "../src/scope/scope-validator.js";
import { ScopeConfigSchema } from "../src/scope/scope-config.js";

describe("ScopeValidator", () => {
  const validator = new ScopeValidator({
    allowedCidrs: ["10.10.11.0/24", "192.168.1.0/24"],
    blockedCidrs: ["127.0.0.0/8", "169.254.0.0/16"],
  });

  it("allows IP within scope", async () => {
    const result = await validator.validate("10.10.11.234");
    expect(result.allowed).toBe(true);
    if (result.allowed) {
      expect(result.matchedCidr).toBe("10.10.11.0/24");
    }
  });

  it("rejects IP outside scope", async () => {
    const result = await validator.validate("8.8.8.8");
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(result.reason).toContain("not within any allowed CIDR");
    }
  });

  it("rejects blocked IPs even if in scope range", async () => {
    const v = new ScopeValidator({
      allowedCidrs: ["127.0.0.0/8"],
      blockedCidrs: ["127.0.0.0/8"],
    });
    const result = await v.validate("127.0.0.1");
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(result.reason).toContain("blocked");
    }
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

// C1: parseCidr and ipToInt input validation
describe("ScopeValidator - CIDR/IP input validation (C1)", () => {
  it("throws on invalid CIDR mask (e.g. /33)", () => {
    expect(
      () => new ScopeValidator({ allowedCidrs: ["10.0.0.0/33"] })
    ).toThrow();
  });

  it("throws on negative CIDR mask (e.g. /-1)", () => {
    expect(
      () => new ScopeValidator({ allowedCidrs: ["10.0.0.0/-1"] })
    ).toThrow();
  });

  it("throws on NaN CIDR mask (e.g. /abc)", () => {
    expect(
      () => new ScopeValidator({ allowedCidrs: ["10.0.0.0/abc"] })
    ).toThrow();
  });

  it("throws on non-integer CIDR mask (e.g. /24.5)", () => {
    expect(
      () => new ScopeValidator({ allowedCidrs: ["10.0.0.0/24.5"] })
    ).toThrow();
  });

  it("throws on IP with wrong number of octets", () => {
    expect(
      () => new ScopeValidator({ allowedCidrs: ["10.0.0/24"] })
    ).toThrow();
  });

  it("throws on IP with too many octets", () => {
    expect(
      () => new ScopeValidator({ allowedCidrs: ["10.0.0.0.0/24"] })
    ).toThrow();
  });

  it("throws on IP octet out of range (e.g. 256)", () => {
    expect(
      () => new ScopeValidator({ allowedCidrs: ["256.0.0.0/24"] })
    ).toThrow();
  });

  it("throws on IP octet that is negative", () => {
    expect(
      () => new ScopeValidator({ allowedCidrs: ["-1.0.0.0/24"] })
    ).toThrow();
  });

  it("throws on IP octet that is non-numeric", () => {
    expect(
      () => new ScopeValidator({ allowedCidrs: ["a.b.c.d/24"] })
    ).toThrow();
  });

  it("throws on empty CIDR string", () => {
    expect(
      () => new ScopeValidator({ allowedCidrs: [""] })
    ).toThrow();
  });

  it("accepts valid /0 CIDR (match all)", () => {
    const v = new ScopeValidator({ allowedCidrs: ["0.0.0.0/0"] });
    // /0 should match any IP
    return v.validate("1.2.3.4").then((result) => {
      expect(result.allowed).toBe(true);
    });
  });

  it("accepts valid /32 CIDR (single host)", () => {
    const v = new ScopeValidator({ allowedCidrs: ["10.0.0.1/32"] });
    return v.validate("10.0.0.1").then((result) => {
      expect(result.allowed).toBe(true);
    });
  });

  it("throws when validate receives an invalid IP", async () => {
    const v = new ScopeValidator({ allowedCidrs: ["10.0.0.0/24"] });
    await expect(v.validate("not-an-ip")).rejects.toThrow();
  });

  it("throws when validate receives IP with out-of-range octet", async () => {
    const v = new ScopeValidator({ allowedCidrs: ["10.0.0.0/24"] });
    await expect(v.validate("10.0.0.999")).rejects.toThrow();
  });
});

// I12: ValidationResult discriminated union
describe("ScopeValidator - ValidationResult discriminated union (I12)", () => {
  it("allowed result has matchedCidr and no reason field", async () => {
    const v = new ScopeValidator({ allowedCidrs: ["10.0.0.0/24"] });
    const result = await v.validate("10.0.0.1");
    expect(result.allowed).toBe(true);
    if (result.allowed) {
      expect(result.matchedCidr).toBeDefined();
      // TypeScript should guarantee matchedCidr exists on allowed: true
      expect(typeof result.matchedCidr).toBe("string");
    }
  });

  it("denied result has reason and no matchedCidr field", async () => {
    const v = new ScopeValidator({ allowedCidrs: ["10.0.0.0/24"] });
    const result = await v.validate("8.8.8.8");
    expect(result.allowed).toBe(false);
    if (!result.allowed) {
      expect(result.reason).toBeDefined();
      expect(typeof result.reason).toBe("string");
    }
  });

  it("type narrowing works correctly for allowed result", async () => {
    const v = new ScopeValidator({ allowedCidrs: ["10.0.0.0/24"] });
    const result: ValidationResult = await v.validate("10.0.0.1");
    if (result.allowed) {
      // This should compile without error: matchedCidr is guaranteed
      const cidr: string = result.matchedCidr;
      expect(cidr).toBe("10.0.0.0/24");
    }
  });

  it("type narrowing works correctly for denied result", async () => {
    const v = new ScopeValidator({ allowedCidrs: ["10.0.0.0/24"] });
    const result: ValidationResult = await v.validate("8.8.8.8");
    if (!result.allowed) {
      // This should compile without error: reason is guaranteed
      const reason: string = result.reason;
      expect(reason).toContain("not within any allowed CIDR");
    }
  });
});

// I9: isToolAllowed wired to restrictions
describe("ScopeValidator - isToolAllowed with restrictions (I9)", () => {
  it("passive tools are always allowed regardless of restrictions", () => {
    const v = new ScopeValidator({
      allowedCidrs: ["10.0.0.0/24"],
      restrictions: {
        allowActiveScanning: false,
        allowExploitation: false,
        allowBruteForce: false,
      },
    });
    expect(v.isToolAllowed("passive")).toBe(true);
  });

  it("active tools allowed when allowActiveScanning is true", () => {
    const v = new ScopeValidator({
      allowedCidrs: ["10.0.0.0/24"],
      restrictions: {
        allowActiveScanning: true,
      },
    });
    expect(v.isToolAllowed("active")).toBe(true);
  });

  it("active tools denied when allowActiveScanning is false", () => {
    const v = new ScopeValidator({
      allowedCidrs: ["10.0.0.0/24"],
      restrictions: {
        allowActiveScanning: false,
      },
    });
    expect(v.isToolAllowed("active")).toBe(false);
  });

  it("invasive tools allowed when both allowExploitation and allowBruteForce are true", () => {
    const v = new ScopeValidator({
      allowedCidrs: ["10.0.0.0/24"],
      restrictions: {
        allowExploitation: true,
        allowBruteForce: true,
      },
    });
    expect(v.isToolAllowed("invasive")).toBe(true);
  });

  it("invasive tools denied when allowExploitation is false", () => {
    const v = new ScopeValidator({
      allowedCidrs: ["10.0.0.0/24"],
      restrictions: {
        allowExploitation: false,
        allowBruteForce: true,
      },
    });
    expect(v.isToolAllowed("invasive")).toBe(false);
  });

  it("invasive tools denied when allowBruteForce is false", () => {
    const v = new ScopeValidator({
      allowedCidrs: ["10.0.0.0/24"],
      restrictions: {
        allowExploitation: true,
        allowBruteForce: false,
      },
    });
    expect(v.isToolAllowed("invasive")).toBe(false);
  });

  it("uses sensible defaults when no restrictions provided", () => {
    const v = new ScopeValidator({
      allowedCidrs: ["10.0.0.0/24"],
    });
    // Defaults: allowActiveScanning: true, allowExploitation: false, allowBruteForce: false
    expect(v.isToolAllowed("passive")).toBe(true);
    expect(v.isToolAllowed("active")).toBe(true);
    expect(v.isToolAllowed("invasive")).toBe(false);
  });

  it("uses sensible defaults when restrictions is empty object-like", () => {
    const v = new ScopeValidator({
      allowedCidrs: ["10.0.0.0/24"],
      restrictions: {},
    });
    // Should get defaults: allowActiveScanning: true, etc.
    expect(v.isToolAllowed("passive")).toBe(true);
    expect(v.isToolAllowed("active")).toBe(true);
    expect(v.isToolAllowed("invasive")).toBe(false);
  });
});

// S9: Zod CIDR format refinement
describe("ScopeConfigSchema - CIDR format validation (S9)", () => {
  it("accepts valid CIDR notation", () => {
    const result = ScopeConfigSchema.safeParse({
      allowedCidrs: ["10.0.0.0/24", "192.168.1.0/16"],
    });
    expect(result.success).toBe(true);
  });

  it("rejects allowedCidrs with plain string (no slash)", () => {
    const result = ScopeConfigSchema.safeParse({
      allowedCidrs: ["not-a-cidr"],
    });
    expect(result.success).toBe(false);
  });

  it("rejects allowedCidrs with IP but no mask", () => {
    const result = ScopeConfigSchema.safeParse({
      allowedCidrs: ["10.0.0.0"],
    });
    expect(result.success).toBe(false);
  });

  it("rejects blockedCidrs with invalid format", () => {
    const result = ScopeConfigSchema.safeParse({
      allowedCidrs: ["10.0.0.0/24"],
      blockedCidrs: ["garbage"],
    });
    expect(result.success).toBe(false);
  });

  it("accepts CIDR with various valid masks", () => {
    const result = ScopeConfigSchema.safeParse({
      allowedCidrs: ["0.0.0.0/0", "255.255.255.255/32", "10.0.0.0/8"],
    });
    expect(result.success).toBe(true);
  });

  it("rejects CIDR with letters in IP", () => {
    const result = ScopeConfigSchema.safeParse({
      allowedCidrs: ["abc.def.ghi.jkl/24"],
    });
    expect(result.success).toBe(false);
  });
});
