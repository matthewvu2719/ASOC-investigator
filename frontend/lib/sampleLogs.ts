// Sample log generators for exercising the masking engine and agent
// pipeline against a few common RAW log shapes — the actual ingested
// event data an analyst would paste, not a formatted alert/detection
// summary. Purely client-side, randomized per click.

const IPS = ["203.0.113.45", "198.51.100.77", "45.33.32.156", "192.0.2.88", "185.220.101.5"];
const DOMAINS = ["evil-c2.example.com", "malicious-update.net", "phish-portal.co"];
const USERS = ["jdoe", "asmith", "mrivera", "khassan", "tlee"];
const HOSTS = ["WKSTN-0472", "WKSTN-1183", "SRV-DB02", "LAPTOP-9F31"];

function pick<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function randomHex(length: number): string {
  let out = "";
  for (let i = 0; i < length; i++) out += Math.floor(Math.random() * 16).toString(16);
  return out;
}

function syslogTimestamp(d: Date): string {
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const day = String(d.getDate()).padStart(2, " ");
  return `${months[d.getMonth()]} ${day} ${d.toTimeString().slice(0, 8)}`;
}

// Raw Azure AD sign-in log events, as ingested into the SignInLogs table
// before any Sentinel alert/incident is generated — repeated failures then
// a success from the same IP.
function generateSentinelRaw(): string {
  const user = pick(USERS);
  const ip = pick(IPS);
  const now = Date.now();
  const attempts = [
    { offsetMs: 0, errorCode: 50126 },
    { offsetMs: 4000, errorCode: 50126 },
    { offsetMs: 9000, errorCode: 50126 },
    { offsetMs: 15000, errorCode: 0 },
  ];
  return attempts
    .map((a) =>
      JSON.stringify({
        time: new Date(now + a.offsetMs).toISOString(),
        operationName: "Sign-in activity",
        category: "SignInLogs",
        properties: {
          userPrincipalName: `${user}@company.com`,
          userDisplayName: user,
          ipAddress: ip,
          clientAppUsed: "Browser",
          deviceDetail: { operatingSystem: "Windows10", browser: "Chrome 115.0.0" },
          location: { city: "Moscow", countryOrRegion: "RU" },
          status:
            a.errorCode === 0
              ? { errorCode: 0 }
              : {
                  errorCode: a.errorCode,
                  failureReason: "Error validating credentials due to invalid username or password.",
                },
          riskLevelDuringSignIn: a.errorCode === 0 ? "high" : "medium",
        },
      })
    )
    .join("\n");
}

// Raw Falcon Data Replicator-style telemetry — a process execution event
// followed by a network connection event, the shape CrowdStrike actually
// streams out, not a formatted "Detection" alert.
function generateCrowdStrikeRaw(): string {
  const host = pick(HOSTS);
  const user = pick(USERS);
  const ip = pick(IPS);
  const sha256 = randomHex(64);
  const now = Date.now();

  const events = [
    {
      event_simpleName: "ProcessRollup2",
      ComputerName: host,
      UserName: `CORP\\${user}`,
      FileName: "powershell.exe",
      CommandLine: "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAA...",
      ParentBaseFileName: "explorer.exe",
      SHA256HashData: sha256,
      LocalAddressIP4: "10.0.5.23",
      timestamp: String(now),
    },
    {
      event_simpleName: "NetworkConnectIP4",
      ComputerName: host,
      UserName: `CORP\\${user}`,
      RemoteAddressIP4: ip,
      RemotePort: "443",
      ConnectionDirection: "1",
      timestamp: String(now + 1200),
    },
  ];
  return events.map((e) => JSON.stringify(e)).join("\n");
}

function generateSplunkSSH(): string {
  const ip = pick(IPS);
  const user = pick(USERS);
  const ts = syslogTimestamp(new Date());
  const pid = 20000 + Math.floor(Math.random() * 9000);
  return `${ts} fw01 sshd[${pid}]: Failed password for invalid user admin from ${ip} port 51244 ssh2
${ts} fw01 sshd[${pid}]: Failed password for invalid user admin from ${ip} port 51244 ssh2
${ts} fw01 sshd[${pid}]: Accepted password for ${user} from ${ip} port 51260 ssh2`;
}

// The actual raw text of a Windows Security Event 4625, as copy-pasted
// from Event Viewer's General tab — this is genuinely what gets pasted
// into tickets, not a condensed field list.
function generateWindowsEventLog(): string {
  const user = pick(USERS);
  const host = pick(HOSTS);
  const ip = pick(IPS);
  const now = new Date();
  return `Log Name:      Security
Source:        Microsoft-Windows-Security-Auditing
Event ID:      4625
Level:         Information
Task Category: Logon
Keywords:      Audit Failure
Logged:        ${now.toLocaleString()}

An account failed to log on.

Subject:
\tSecurity ID:\t\tS-1-0-0
\tAccount Name:\t\t-
\tAccount Domain:\t\t-
\tLogon ID:\t\t0x0

Logon Type:\t\t\t3

Account For Which Logon Failed:
\tSecurity ID:\t\tS-1-0-0
\tAccount Name:\t\t${user}
\tAccount Domain:\t\tCORP

Failure Information:
\tFailure Reason:\t\tUnknown user name or bad password.
\tStatus:\t\t\t0xC000006D
\tSub Status:\t\t0xC0000064

Process Information:
\tCaller Process ID:\t0x0
\tCaller Process Name:\t-

Network Information:
\tWorkstation Name:\t${host}
\tSource Network Address:\t${ip}
\tSource Port:\t\t51244`;
}

// Raw proxy access-log line (Squid/Bluecoat-style), not a normalized alert.
function generateProxyLog(): string {
  const user = pick(USERS);
  const domain = pick(DOMAINS);
  const ip = pick(IPS);
  const ts = new Date().toISOString().replace("T", " ").slice(0, 19);
  return `${ts} ${ip} ${user} DENIED "Malicious Sites and Malware" http://${domain}/payload.bin 200 TCP_MISS 1240 0 GET application/octet-stream -`;
}

export interface SampleLogGenerator {
  label: string;
  generate: () => string;
}

export const SAMPLE_LOG_GENERATORS: SampleLogGenerator[] = [
  { label: "Sentinel (raw)", generate: generateSentinelRaw },
  { label: "CrowdStrike (raw)", generate: generateCrowdStrikeRaw },
  { label: "Splunk (SSH)", generate: generateSplunkSSH },
  { label: "Windows Event Log", generate: generateWindowsEventLog },
  { label: "Proxy log", generate: generateProxyLog },
];
