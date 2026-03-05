import { ScopeConfig } from "./scope-config.js";

export type ValidationResult =
  | { allowed: true; matchedCidr: string }
  | { allowed: false; reason: string };

interface Restrictions {
  allowActiveScanning: boolean;
  allowExploitation: boolean;
  allowBruteForce: boolean;
}

const DEFAULT_RESTRICTIONS: Restrictions = {
  allowActiveScanning: true,
  allowExploitation: false,
  allowBruteForce: false,
};

export class ScopeValidator {
  private allowedCidrs: CidrRange[];
  private blockedCidrs: CidrRange[];
  private restrictions: Restrictions;

  constructor(
    config: Pick<ScopeConfig, "allowedCidrs" | "blockedCidrs" | "restrictions">
  ) {
    this.allowedCidrs = config.allowedCidrs.map(parseCidr);
    this.blockedCidrs = (config.blockedCidrs ?? []).map(parseCidr);
    this.restrictions = {
      ...DEFAULT_RESTRICTIONS,
      ...config.restrictions,
    };
  }

  async validate(target: string): Promise<ValidationResult> {
    const ip = target; // TODO: DNS resolution for hostnames

    // Validate the target IP before checking ranges
    validateIp(ip);

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
    // Passive tools are always allowed
    if (riskLevel === "passive") return true;

    // Active tools require allowActiveScanning
    if (riskLevel === "active") return this.restrictions.allowActiveScanning;

    // Invasive tools require both allowExploitation and allowBruteForce
    return (
      this.restrictions.allowExploitation && this.restrictions.allowBruteForce
    );
  }
}

interface CidrRange {
  original: string;
  networkInt: number;
  maskInt: number;
}

function validateIp(ip: string): void {
  const parts = ip.split(".");
  if (parts.length !== 4) {
    throw new Error(`Invalid IP address "${ip}": expected 4 octets`);
  }
  for (const part of parts) {
    const num = Number(part);
    if (!Number.isInteger(num) || num < 0 || num > 255 || part === "") {
      throw new Error(
        `Invalid IP address "${ip}": octet "${part}" is not a valid integer 0-255`
      );
    }
  }
}

function parseCidr(cidr: string): CidrRange {
  const [ip, bits] = cidr.split("/");

  // Validate IP portion
  if (!ip) {
    throw new Error(`Invalid CIDR "${cidr}": missing IP address`);
  }
  validateIp(ip);

  // Validate mask portion
  if (bits === undefined || bits === "") {
    throw new Error(`Invalid CIDR "${cidr}": missing mask`);
  }
  const mask = Number(bits);
  if (!Number.isInteger(mask) || mask < 0 || mask > 32) {
    throw new Error(
      `Invalid CIDR "${cidr}": mask must be an integer between 0 and 32`
    );
  }

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
