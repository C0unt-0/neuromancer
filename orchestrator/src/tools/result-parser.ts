export interface ToolResult {
  toolId: string;
  targetIp: string;
  timestamp: number;
  discoveries: Discovery[];
}

export interface Discovery {
  type: "port" | "service" | "vulnerability" | "directory" | "credential" | "domain";
  port?: number;
  protocol?: "tcp" | "udp";
  state?: "open" | "filtered" | "closed";
  serviceName?: string;
  serviceVersion?: string;
  vulnId?: string;
  vulnSeverity?: "critical" | "high" | "medium" | "low" | "info";
  vulnTitle?: string;
  path?: string;
  statusCode?: number;
  raw?: string;
}

/**
 * Parse nmap XML output into structured discoveries.
 * Uses regex-based parsing — sufficient for nmap's predictable XML format.
 */
export function parseNmapXml(xml: string, targetIp: string): ToolResult {
  const discoveries: Discovery[] = [];

  // Match each <port> block
  const portRegex = /<port protocol="(\w+)" portid="(\d+)">([\s\S]*?)<\/port>/g;
  let portMatch: RegExpExecArray | null;

  while ((portMatch = portRegex.exec(xml)) !== null) {
    const proto = portMatch[1] as "tcp" | "udp";
    const portNum = parseInt(portMatch[2], 10);
    const portBlock = portMatch[3];

    // Extract state
    const stateMatch = portBlock.match(/<state state="(\w+)"/);
    const state = stateMatch?.[1] as "open" | "filtered" | "closed" | undefined;

    // Skip non-open ports
    if (state && state !== "open") continue;

    // Extract service info
    const serviceMatch = portBlock.match(
      /<service\s+name="([^"]*)"(?:\s+product="([^"]*)")?(?:\s+version="([^"]*)")?/
    );
    const serviceName = serviceMatch?.[1];
    const product = serviceMatch?.[2];
    const version = serviceMatch?.[3];
    const serviceVersion =
      product && version ? `${product} ${version}` : product || version || undefined;

    discoveries.push({
      type: "port",
      port: portNum,
      protocol: proto,
      state: state ?? "open",
      serviceName,
      serviceVersion,
    });

    // Extract script results (vulns within the port)
    const scriptRegex = /<script id="([^"]*)" output="([^"]*)"/g;
    let scriptMatch: RegExpExecArray | null;
    while ((scriptMatch = scriptRegex.exec(portBlock)) !== null) {
      const scriptId = scriptMatch[1];
      const scriptOutput = scriptMatch[2];

      // Check for CVE references
      const cveRegex = /CVE-\d{4}-\d{4,}/g;
      let cveMatch: RegExpExecArray | null;
      while ((cveMatch = cveRegex.exec(scriptOutput)) !== null) {
        discoveries.push({
          type: "vulnerability",
          port: portNum,
          protocol: proto,
          vulnId: cveMatch[0],
          vulnSeverity: "medium",
          vulnTitle: `${scriptId}: ${cveMatch[0]}`,
          raw: scriptOutput,
        });
      }
    }
  }

  // Extract OS detection if present
  const osMatch = xml.match(/<osmatch name="([^"]*)" accuracy="(\d+)"/);
  if (osMatch) {
    discoveries.push({
      type: "service",
      serviceName: "os-detection",
      serviceVersion: osMatch[1],
      raw: `Accuracy: ${osMatch[2]}%`,
    });
  }

  return {
    toolId: "nmap-scan",
    targetIp,
    timestamp: Date.now(),
    discoveries,
  };
}

/**
 * Parse nuclei JSONL output into structured discoveries.
 * Each line is a JSON object representing a finding.
 */
export function parseNucleiJson(jsonl: string, targetIp: string): ToolResult {
  const discoveries: Discovery[] = [];
  const lines = jsonl.trim().split("\n").filter(Boolean);

  for (const line of lines) {
    try {
      const finding = JSON.parse(line) as NucleiFinding;

      const severity = normalizeSeverity(finding.info?.severity);
      const vulnId = finding["template-id"];

      discoveries.push({
        type: "vulnerability",
        vulnId,
        vulnSeverity: severity,
        vulnTitle: finding.info?.name ?? finding["template-id"],
        raw: line,
      });
    } catch {
      continue;
    }
  }

  return {
    toolId: "nuclei-scan",
    targetIp,
    timestamp: Date.now(),
    discoveries,
  };
}

/**
 * Parse gobuster output into directory discoveries.
 * Output format: /path (Status: 200) [Size: 1234]
 */
export function parseGobusterOutput(output: string, targetIp: string): ToolResult {
  const discoveries: Discovery[] = [];
  const lineRegex = /^(\/\S+)\s+\(Status:\s*(\d+)\)/gm;
  let match: RegExpExecArray | null;

  while ((match = lineRegex.exec(output)) !== null) {
    discoveries.push({
      type: "directory",
      path: match[1],
      statusCode: parseInt(match[2], 10),
    });
  }

  return {
    toolId: "gobuster-dir",
    targetIp,
    timestamp: Date.now(),
    discoveries,
  };
}

/**
 * Route tool output to the appropriate parser.
 */
export function parseToolOutput(
  toolId: string,
  output: string,
  targetIp: string
): ToolResult {
  switch (toolId) {
    case "nmap-scan":
      return parseNmapXml(output, targetIp);
    case "nuclei-scan":
      return parseNucleiJson(output, targetIp);
    case "gobuster-dir":
      return parseGobusterOutput(output, targetIp);
    default:
      return {
        toolId,
        targetIp,
        timestamp: Date.now(),
        discoveries: [],
      };
  }
}

// --- Internal types ---

interface NucleiFinding {
  "template-id": string;
  info?: {
    severity?: string;
    name?: string;
  };
  host?: string;
  "matched-at"?: string;
}

function normalizeSeverity(
  s?: string
): "critical" | "high" | "medium" | "low" | "info" {
  switch (s?.toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    default:
      return "info";
  }
}
