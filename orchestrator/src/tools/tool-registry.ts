import { z } from "zod";

export interface ToolDefinition {
  id: string;
  name: string;
  description: string;
  category: "recon" | "scanning" | "exploit" | "auth" | "webapp" | "osint";
  icon: string;
  color: string;
  command: string;
  paramSchema: z.ZodSchema;
  buildCommand: (params: Record<string, unknown>) => string;
  capabilities: string[];
  structuredOutputFlag?: string;
  outputParser?: "nmap-xml" | "nuclei-json" | "json-lines" | "plain";
  requiresScope: boolean;
  riskLevel: "passive" | "active" | "invasive";
  estimatedDurationSec: number;
}

export const TOOLS: Record<string, ToolDefinition> = {
  "nmap-scan": {
    id: "nmap-scan",
    name: "Port Scan (nmap)",
    description: "Discover open ports and running services",
    category: "recon",
    icon: "🔍",
    color: "#00f0ff",
    command: "nmap",
    paramSchema: z.object({
      target: z.string().min(1),
      ports: z.string().optional().default("-"),
      flags: z.string().optional().default("-sV -sC -T4"),
      scripts: z.string().optional(),
    }),
    buildCommand: (p) => {
      let cmd = `nmap ${p.flags} -p ${p.ports}`;
      if (p.scripts) cmd += ` --script=${p.scripts}`;
      cmd += ` -oX - ${p.target}`;
      return cmd;
    },
    capabilities: ["CAP_NET_RAW", "CAP_NET_ADMIN"],
    structuredOutputFlag: "-oX -",
    outputParser: "nmap-xml",
    requiresScope: true,
    riskLevel: "active",
    estimatedDurationSec: 30,
  },

  "nuclei-scan": {
    id: "nuclei-scan",
    name: "Vulnerability Scan (nuclei)",
    description: "Check for known vulnerabilities using 8000+ templates",
    category: "scanning",
    icon: "🛡",
    color: "#ff3344",
    command: "nuclei",
    paramSchema: z.object({
      target: z.string().min(1),
      severity: z.string().optional().default("critical,high,medium"),
      tags: z.string().optional(),
    }),
    buildCommand: (p) => {
      let cmd = `nuclei -target ${p.target} -severity ${p.severity} -jsonl`;
      if (p.tags) cmd += ` -tags ${p.tags}`;
      return cmd;
    },
    capabilities: [],
    outputParser: "nuclei-json",
    requiresScope: true,
    riskLevel: "active",
    estimatedDurationSec: 120,
  },

  "gobuster-dir": {
    id: "gobuster-dir",
    name: "Directory Brute Force (gobuster)",
    description: "Discover hidden directories and files on web servers",
    category: "webapp",
    icon: "🕷",
    color: "#ff8844",
    command: "gobuster",
    paramSchema: z.object({
      target: z.string().url(),
      wordlist: z
        .string()
        .optional()
        .default("/usr/share/seclists/Discovery/Web-Content/common.txt"),
      extensions: z.string().optional(),
    }),
    buildCommand: (p) => {
      let cmd = `gobuster dir -u ${p.target} -w ${p.wordlist} -o /dev/stdout --no-color`;
      if (p.extensions) cmd += ` -x ${p.extensions}`;
      return cmd;
    },
    capabilities: [],
    outputParser: "plain",
    requiresScope: true,
    riskLevel: "active",
    estimatedDurationSec: 60,
  },

  "whois-lookup": {
    id: "whois-lookup",
    name: "WHOIS Lookup",
    description: "Query domain/IP registration information",
    category: "osint",
    icon: "📋",
    color: "#aa88ff",
    command: "whois",
    paramSchema: z.object({
      target: z.string().min(1),
    }),
    buildCommand: (p) => `whois ${p.target}`,
    capabilities: [],
    outputParser: "plain",
    requiresScope: false,
    riskLevel: "passive",
    estimatedDurationSec: 5,
  },

  "dig-dns": {
    id: "dig-dns",
    name: "DNS Lookup (dig)",
    description: "Query DNS records for a domain",
    category: "recon",
    icon: "📖",
    color: "#f0ff00",
    command: "dig",
    paramSchema: z.object({
      target: z.string().min(1),
      recordType: z.string().optional().default("ANY"),
    }),
    buildCommand: (p) => `dig ${p.target} ${p.recordType} +noall +answer`,
    capabilities: [],
    outputParser: "plain",
    requiresScope: false,
    riskLevel: "passive",
    estimatedDurationSec: 3,
  },

  traceroute: {
    id: "traceroute",
    name: "Traceroute",
    description: "Trace network path to target",
    category: "recon",
    icon: "🔗",
    color: "#00ff88",
    command: "traceroute",
    paramSchema: z.object({
      target: z.string().min(1),
    }),
    buildCommand: (p) => `traceroute -n ${p.target}`,
    capabilities: ["CAP_NET_RAW"],
    outputParser: "plain",
    requiresScope: true,
    riskLevel: "active",
    estimatedDurationSec: 15,
  },

  "custom-script": {
    id: "custom-script",
    name: "Custom Script",
    description: "Execute a generated Python/Bash script in sandbox",
    category: "recon",
    icon: "📝",
    color: "#ff00c8",
    command: "python3",
    paramSchema: z.object({
      script: z.string().min(1),
      language: z.enum(["python", "bash"]),
      args: z.string().optional(),
    }),
    buildCommand: (p) => {
      if (p.language === "python")
        return `python3 /tmp/script.py ${p.args || ""}`;
      return `bash /tmp/script.sh ${p.args || ""}`;
    },
    capabilities: [],
    outputParser: "plain",
    requiresScope: true,
    riskLevel: "invasive",
    estimatedDurationSec: 30,
  },
};

export function getTool(id: string): ToolDefinition | undefined {
  return TOOLS[id];
}

export function listTools(): ToolDefinition[] {
  return Object.values(TOOLS);
}

export function getToolsByCategory(
  category: ToolDefinition["category"]
): ToolDefinition[] {
  return Object.values(TOOLS).filter((t) => t.category === category);
}
