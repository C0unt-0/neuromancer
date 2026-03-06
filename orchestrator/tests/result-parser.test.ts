import { describe, it, expect } from "vitest";
import {
  parseNmapXml,
  parseNucleiJson,
  parseGobusterOutput,
  parseToolOutput,
} from "../src/tools/result-parser.js";

const SAMPLE_NMAP_XML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.10.11.234" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.41"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="Apache httpd" version="2.4.41"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="filtered"/>
        <service name="mysql"/>
      </port>
    </ports>
  </host>
</nmaprun>`;

describe("parseNmapXml", () => {
  it("extracts open ports with services", () => {
    const result = parseNmapXml(SAMPLE_NMAP_XML, "10.10.11.234");

    expect(result.toolId).toBe("nmap-scan");
    expect(result.targetIp).toBe("10.10.11.234");
    // Should have 3 open ports (filtered port 3306 excluded)
    expect(result.discoveries.length).toBe(3);

    const ssh = result.discoveries.find((d) => d.port === 22);
    expect(ssh).toBeDefined();
    expect(ssh!.type).toBe("port");
    expect(ssh!.protocol).toBe("tcp");
    expect(ssh!.state).toBe("open");
    expect(ssh!.serviceName).toBe("ssh");
    expect(ssh!.serviceVersion).toBe("OpenSSH 8.2p1");
  });

  it("skips filtered ports", () => {
    const result = parseNmapXml(SAMPLE_NMAP_XML, "10.10.11.234");
    const filtered = result.discoveries.find((d) => d.port === 3306);
    expect(filtered).toBeUndefined();
  });

  it("handles empty XML", () => {
    const result = parseNmapXml("<nmaprun></nmaprun>", "10.10.11.234");
    expect(result.discoveries.length).toBe(0);
  });

  it("extracts OS match if present", () => {
    const xmlWithOs = `<nmaprun>
      <host>
        <osmatch name="Linux 5.4" accuracy="96"/>
      </host>
    </nmaprun>`;
    const result = parseNmapXml(xmlWithOs, "10.10.11.234");
    const os = result.discoveries.find((d) => d.serviceName === "os-detection");
    expect(os).toBeDefined();
    expect(os!.serviceVersion).toBe("Linux 5.4");
  });
});

const SAMPLE_NUCLEI_JSONL = [
  '{"template-id":"apache-detect","info":{"severity":"info","name":"Apache Detection"},"host":"http://10.10.11.234","matched-at":"http://10.10.11.234"}',
  '{"template-id":"CVE-2021-41773","info":{"severity":"critical","name":"Apache Path Traversal"},"host":"http://10.10.11.234","matched-at":"http://10.10.11.234/icons/.%2e/%2e%2e/etc/passwd"}',
  '{"template-id":"CVE-2023-25690","info":{"severity":"high","name":"Apache HTTP Request Smuggling"},"host":"http://10.10.11.234"}',
].join("\n");

describe("parseNucleiJson", () => {
  it("extracts vulnerabilities with severity", () => {
    const result = parseNucleiJson(SAMPLE_NUCLEI_JSONL, "10.10.11.234");

    expect(result.toolId).toBe("nuclei-scan");
    expect(result.discoveries.length).toBe(3);

    const critical = result.discoveries.find(
      (d) => d.vulnSeverity === "critical"
    );
    expect(critical).toBeDefined();
    expect(critical!.vulnId).toBe("CVE-2021-41773");
    expect(critical!.vulnTitle).toBe("Apache Path Traversal");
  });

  it("assigns info severity to unknown levels", () => {
    const jsonl = '{"template-id":"test","info":{"name":"Test"}}';
    const result = parseNucleiJson(jsonl, "10.10.11.234");
    expect(result.discoveries[0].vulnSeverity).toBe("info");
  });

  it("skips malformed lines", () => {
    const jsonl = 'not json\n{"template-id":"valid","info":{"severity":"low","name":"Valid"}}';
    const result = parseNucleiJson(jsonl, "10.10.11.234");
    expect(result.discoveries.length).toBe(1);
    expect(result.discoveries[0].vulnId).toBe("valid");
  });

  it("handles empty input", () => {
    const result = parseNucleiJson("", "10.10.11.234");
    expect(result.discoveries.length).toBe(0);
  });
});

describe("parseGobusterOutput", () => {
  it("extracts directories with status codes", () => {
    const output = `/admin (Status: 200) [Size: 1234]
/login (Status: 302) [Size: 0]
/api (Status: 403) [Size: 567]
Progress: 4614 / 4615 (99.98%)`;

    const result = parseGobusterOutput(output, "10.10.11.234");
    expect(result.discoveries.length).toBe(3);

    expect(result.discoveries[0].type).toBe("directory");
    expect(result.discoveries[0].path).toBe("/admin");
    expect(result.discoveries[0].statusCode).toBe(200);

    expect(result.discoveries[1].path).toBe("/login");
    expect(result.discoveries[1].statusCode).toBe(302);
  });

  it("handles empty output", () => {
    const result = parseGobusterOutput("", "10.10.11.234");
    expect(result.discoveries.length).toBe(0);
  });
});

describe("parseToolOutput", () => {
  it("routes nmap output to nmap parser", () => {
    const result = parseToolOutput("nmap-scan", SAMPLE_NMAP_XML, "10.10.11.234");
    expect(result.toolId).toBe("nmap-scan");
    expect(result.discoveries.length).toBeGreaterThan(0);
  });

  it("routes nuclei output to nuclei parser", () => {
    const result = parseToolOutput("nuclei-scan", SAMPLE_NUCLEI_JSONL, "10.10.11.234");
    expect(result.toolId).toBe("nuclei-scan");
    expect(result.discoveries.length).toBeGreaterThan(0);
  });

  it("returns empty discoveries for plain output tools", () => {
    const result = parseToolOutput("whois-lookup", "some whois output", "10.10.11.234");
    expect(result.discoveries.length).toBe(0);
  });
});
