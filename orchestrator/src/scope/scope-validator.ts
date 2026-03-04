import { ScopeConfig } from "./scope-config.js";

export interface ValidationResult {
  allowed: boolean;
  reason?: string;
  resolvedIp?: string;
  matchedCidr?: string;
}

export class ScopeValidator {
  private allowedCidrs: CidrRange[];
  private blockedCidrs: CidrRange[];

  constructor(config: Pick<ScopeConfig, "allowedCidrs" | "blockedCidrs">) {
    this.allowedCidrs = config.allowedCidrs.map(parseCidr);
    this.blockedCidrs = (config.blockedCidrs ?? []).map(parseCidr);
  }

  async validate(target: string): Promise<ValidationResult> {
    const ip = target; // TODO: DNS resolution for hostnames

    // Check blocklist first
    for (const cidr of this.blockedCidrs) {
      if (ipInCidr(ip, cidr)) {
        return {
          allowed: false,
          reason: `Target ${ip} is in blocked range ${cidr.original}`,
        };
      }
    }

    // Check allowlist
    for (const cidr of this.allowedCidrs) {
      if (ipInCidr(ip, cidr)) {
        return { allowed: true, matchedCidr: cidr.original };
      }
    }

    return {
      allowed: false,
      reason: `Target ${ip} is not within any allowed CIDR range`,
    };
  }

  isToolAllowed(riskLevel: "passive" | "active" | "invasive"): boolean {
    // Passive tools always allowed, active/invasive checked against restrictions
    return riskLevel === "passive";
  }
}

interface CidrRange {
  original: string;
  networkInt: number;
  maskInt: number;
}

function parseCidr(cidr: string): CidrRange {
  const [ip, bits] = cidr.split("/");
  const mask = bits ? parseInt(bits, 10) : 32;
  return {
    original: cidr,
    networkInt: ipToInt(ip),
    maskInt: mask === 0 ? 0 : (~0 << (32 - mask)) >>> 0,
  };
}

function ipToInt(ip: string): number {
  const parts = ip.split(".").map(Number);
  return (
    ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0
  );
}

function ipInCidr(ip: string, cidr: CidrRange): boolean {
  const ipInt = ipToInt(ip);
  return (ipInt & cidr.maskInt) === (cidr.networkInt & cidr.maskInt);
}
