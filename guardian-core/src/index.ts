import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import fs from 'fs';
import path from 'path';
import net from 'net';
import os from 'os';
import { exec } from 'child_process';
import { promisify } from 'util';
import { 
  AgentRecord, 
  DiscoveredDevice, 
  EDRAlert, 
  EDREvent, 
  FileTelemetry, 
  NetworkTelemetry, 
  ProcessTelemetry, 
  QuarantineRecord, 
  RuleDefinition, 
  SecurityFinding,
  SystemInventory, 
  TelemetryPayload,
  YaraRule
} from './types.js';
import { 
  initDatabase, 
  isDbConnected, 
  saveAgentToDb, 
  saveAlertToDb, 
  saveTelemetryToDb,
  saveDiscoveredDevicesToDb,
  loadDiscoveredDevicesFromDb,
  loadAgentsFromDb,
  deleteAgentFromDb
} from './db.js';

const app = express();
const PORT = process.env.PORT || 4000;
const VALID_AGENT_TOKEN = 'GUARDIAN-SECRET-AGENT-KEY-v0.9';
const execAsync = promisify(exec);
const isWindows = process.platform === 'win32';

app.use(cors());
app.use(express.json());

// State Holders (SQL Backed)
let agents = new Map<string, AgentRecord>();
let eventsHistory: EDREvent[] = [];
let alertsHistory: EDRAlert[] = [];
let quarantineHistory: QuarantineRecord[] = [];
let discoveredDevices: DiscoveredDevice[] = [];
let sseClients: Response[] = [];

// Deep Detection State Trackers
const agentTelemetryHistory = new Map<string, {
  prevConnectionCount: number;
  prevTimestamp: number;
  connectionTargets: Map<string, number>; // "ip:port" -> consecutive heartbeat count
}>();

let activeRules: RuleDefinition[] = [
  {
    ruleId: 'RULE-WIN-001',
    name: 'PowerShell Encoded Command Execution',
    category: 'PROCESS',
    severity: 'HIGH',
    description: 'Detects powershell.exe executing base64 encoded payloads (-EncodedCommand / -enc) [MITRE T1059.001]',
    enabled: true,
  },
  {
    ruleId: 'RULE-FILE-002',
    name: 'Ransomware Mass File Alteration Spike',
    category: 'FILE',
    severity: 'CRITICAL',
    description: 'Detects rapid mass modification or renaming of files in user directories [MITRE T1486]',
    enabled: true,
  },
  {
    ruleId: 'RULE-NET-003',
    name: 'Suspicious Remote Port Outbound Socket',
    category: 'NETWORK',
    severity: 'HIGH',
    description: 'Detects outbound connections to non-standard remote ports (ex: 4444, 6667, 1337) [MITRE T1071]',
    enabled: true,
  },
  {
    ruleId: 'RULE-RES-004',
    name: 'Endpoint High Resource Exhaustion Spike',
    category: 'BEHAVIOR',
    severity: 'WARNING',
    description: 'Triggers when endpoint CPU exceeds 85% or Memory exceeds 90% [MITRE T1499]',
    enabled: true,
  },
  {
    ruleId: 'RULE-MEM-005',
    name: 'LSASS Memory Credential Dumping Attempt',
    category: 'PROCESS',
    severity: 'CRITICAL',
    description: 'Detects processes reading or dumping lsass.exe memory for credential harvesting [MITRE T1003.001]',
    enabled: true,
  },
  {
    ruleId: 'RULE-REG-006',
    name: 'Registry Run Key Auto-Start Persistence Addition',
    category: 'BEHAVIOR',
    severity: 'WARNING',
    description: 'Detects registry additions to autostart keys (HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run) [MITRE T1547.001]',
    enabled: true,
  },
  {
    ruleId: 'RULE-SYS-007',
    name: 'Unauthorized System File Alteration in System32',
    category: 'FILE',
    severity: 'HIGH',
    description: 'Detects modification of critical Windows drivers or system binaries [MITRE T1554]',
    enabled: true,
  },
  {
    ruleId: 'RULE-NET-008',
    name: 'DNS Tunneling High Frequency Query Exfiltration',
    category: 'NETWORK',
    severity: 'HIGH',
    description: 'Detects high frequency UDP port 53 traffic used for C2 covert data exfiltration [MITRE T1071.004]',
    enabled: true,
  },
  {
    ruleId: 'RULE-CMD-009',
    name: 'WMI Administrative Command Line Execution',
    category: 'PROCESS',
    severity: 'INFO',
    description: 'Detects wmic.exe executing administrative queries or remote code invocation [MITRE T1047]',
    enabled: true,
  },
  {
    ruleId: 'RULE-PROC-010',
    name: 'Process Masquerading Path Mismatch',
    category: 'PROCESS',
    severity: 'CRITICAL',
    description: 'Detects system binaries (ex: svchost.exe) executing outside System32 directory [MITRE T1036]',
    enabled: true,
  },
  {
    ruleId: 'RULE-AND-011',
    name: 'Android Untrusted APK Payload / Shell Dropper',
    category: 'FILE',
    severity: 'HIGH',
    description: 'Detects untrusted binary scripts or APK payloads dropped in Android storage [MITRE T1476]',
    enabled: true,
  },
  {
    ruleId: 'RULE-MASQ-012',
    name: 'System Binary Path Masquerading',
    category: 'PROCESS',
    severity: 'CRITICAL',
    description: 'Detects svchost/csrss/lsass/services.exe running from outside System32 [MITRE T1036.005]',
    enabled: true,
  },
  {
    ruleId: 'RULE-CHAIN-013',
    name: 'Suspicious Parent-Child Process Chain',
    category: 'PROCESS',
    severity: 'HIGH',
    description: 'Detects Office apps spawning cmd/powershell or svchost with wrong parent [MITRE T1059]',
    enabled: true,
  },
  {
    ruleId: 'RULE-LOL-014',
    name: 'Living-off-the-Land Binary Execution',
    category: 'PROCESS',
    severity: 'HIGH',
    description: 'Detects certutil/mshta/regsvr32/rundll32/bitsadmin/wscript/cscript execution [MITRE T1218]',
    enabled: true,
  },
  {
    ruleId: 'RULE-BEACON-015',
    name: 'C2 Beaconing Regular Interval Detection',
    category: 'NETWORK',
    severity: 'CRITICAL',
    description: 'Detects regular-interval outbound connections to same IP:port across heartbeats [MITRE T1071.001]',
    enabled: true,
  },
  {
    ruleId: 'RULE-EXFIL-016',
    name: 'Data Exfiltration Connection Volume Spike',
    category: 'NETWORK',
    severity: 'HIGH',
    description: 'Detects 3x+ spike in outbound connections vs previous heartbeat [MITRE T1041]',
    enabled: true,
  },
  {
    ruleId: 'RULE-MINER-017',
    name: 'Cryptominer High CPU Anomaly',
    category: 'BEHAVIOR',
    severity: 'HIGH',
    description: 'Detects sustained high CPU from non-system processes (potential cryptominer) [MITRE T1496]',
    enabled: true,
  },
  {
    ruleId: 'RULE-LATERAL-018',
    name: 'Lateral Movement Outbound Connection',
    category: 'NETWORK',
    severity: 'HIGH',
    description: 'Detects outbound SMB/RDP/WinRM/SSH from non-admin processes [MITRE T1021]',
    enabled: true,
  },
  {
    ruleId: 'RULE-FINDING-019',
    name: 'Agent Deep Security Finding Escalation',
    category: 'BEHAVIOR',
    severity: 'HIGH',
    description: 'Escalates HIGH/CRITICAL security findings reported by endpoint agents',
    enabled: true,
  },
  {
    ruleId: 'RULE-YARA-020',
    name: 'YARA Signature Match Detection',
    category: 'FILE',
    severity: 'CRITICAL',
    description: 'Triggers when a file matches a known YARA malware signature (Mimikatz, Cobalt Strike, Webshell, Ransomware)',
    enabled: true,
  },
];

// Built-in YARA Rules Database
const builtInYaraRules: YaraRule[] = [
  {
    ruleId: 'YARA-MIMIKATZ-01',
    name: 'Mimikatz Credential Harvester Signature',
    threatType: 'MIMIKATZ',
    severity: 'CRITICAL',
    strings: ['sekurlsa::logonpasswords', 'lsadump::sam', 'privilege::debug', 'crypto::certificates', 'dpapi::chrome'],
    description: 'Detects Mimikatz memory/sam dumping commands and strings [MITRE T1003]',
    mitreId: 'T1003'
  },
  {
    ruleId: 'YARA-COBALT-02',
    name: 'Cobalt Strike Beacon Signature',
    threatType: 'COBALT_STRIKE',
    severity: 'CRITICAL',
    strings: ['ReflectiveLoader', '%s as %s\\%s: %d', 'beacon.dll', 'postex_x64.dll', 'postex_x86.dll'],
    description: 'Detects Cobalt Strike beacon reflective DLL injection indicators [MITRE T1055]',
    mitreId: 'T1055'
  },
  {
    ruleId: 'YARA-WEBSHELL-03',
    name: 'WebShell Script Injection Signature',
    threatType: 'WEBSHELL',
    severity: 'HIGH',
    strings: ['c99shell', 'r57shell', 'eval(base64_decode(', 'system($_GET[', 'exec($_POST['],
    description: 'Detects PHP/ASP webshell execution and backdoor payloads [MITRE T1505.003]',
    mitreId: 'T1505.003'
  },
  {
    ruleId: 'YARA-RANSOM-04',
    name: 'Ransomware Note / Key Signature',
    threatType: 'RANSOMWARE',
    severity: 'CRITICAL',
    strings: ['YOUR_FILES_ARE_ENCRYPTED', 'DECRYPT_INSTRUCTIONS', 'LockBit 3.0', 'WanaDecryptor', 'ContiLocker'],
    description: 'Detects ransomware ransom note text and encryption signatures [MITRE T1486]',
    mitreId: 'T1486'
  }
];

// Helper to Auto-Detect Real Subnets from Local System Adapters
function getLocalSubnets(): string[] {
  const interfaces = os.networkInterfaces();
  const subnets = new Set<string>();

  for (const name of Object.keys(interfaces)) {
    const adapter = interfaces[name];
    if (!adapter) continue;
    for (const iface of adapter) {
      if (iface.family === 'IPv4' && !iface.internal) {
        const parts = iface.address.split('.');
        if (parts.length === 4) {
          const subnetPrefix = `${parts[0]}.${parts[1]}.${parts[2]}`;
          subnets.add(subnetPrefix);
        }
      }
    }
  }

  const sorted = Array.from(subnets).sort((a, b) => {
    const aIs50 = a === '192.168.50';
    const bIs50 = b === '192.168.50';
    if (aIs50 && !bIs50) return -1;
    if (!aIs50 && bIs50) return 1;
    const aIs192 = a.startsWith('192.168');
    const bIs192 = b.startsWith('192.168');
    if (aIs192 && !bIs192) return -1;
    if (!aIs192 && bIs192) return 1;
    return a.localeCompare(b);
  });

  return sorted.length > 0 ? sorted : ['192.168.50'];
}

// Broadcast Real-time Server-Sent Events (SSE)
function broadcastSSE(event: string, data: any) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  sseClients = sseClients.filter((res) => {
    try { res.write(payload); return true; } catch { return false; }
  });
}

// Security Token Authentication Middleware
function verifyAgentToken(req: Request, res: Response, next: NextFunction) {
  const token = req.headers['x-guardian-token'];
  if (!token || token !== VALID_AGENT_TOKEN) {
    console.warn(`🔒 Unauthorized agent request blocked from IP ${req.ip}. Header: ${token}`);
    return res.status(401).json({ error: 'Unauthorized: Invalid or missing x-guardian-token header' });
  }
  next();
}

function readField<T = any>(source: any, camel: string, snake: string, fallback?: T): T {
  return (source?.[camel] ?? source?.[snake] ?? fallback) as T;
}

function normalizeInventory(raw: any): SystemInventory {
  return {
    hostname: readField(raw, 'hostname', 'hostname', 'UNKNOWN-HOST'),
    osName: readField(raw, 'osName', 'os_name', 'Unknown OS'),
    osVersion: readField(raw, 'osVersion', 'os_version', 'Unknown'),
    architecture: readField(raw, 'architecture', 'architecture', process.arch),
    cpuModel: readField(raw, 'cpuModel', 'cpu_model', 'Unknown CPU'),
    totalMemoryMb: Number(readField(raw, 'totalMemoryMb', 'total_memory_mb', 0)),
    ipAddress: readField(raw, 'ipAddress', 'ip_address', ''),
    macAddress: readField(raw, 'macAddress', 'mac_address', ''),
  };
}

function normalizeTelemetry(raw: any): TelemetryPayload {
  return {
    agentId: readField(raw, 'agentId', 'agent_id', ''),
    timestamp: readField(raw, 'timestamp', 'timestamp', new Date().toISOString()),
    cpuUsagePct: Number(readField(raw, 'cpuUsagePct', 'cpu_usage_pct', 0)),
    memoryUsagePct: Number(readField(raw, 'memoryUsagePct', 'memory_usage_pct', 0)),
    diskUsagePct: Number(readField(raw, 'diskUsagePct', 'disk_usage_pct', 0)),
    activeProcessesCount: Number(readField(raw, 'activeProcessesCount', 'active_processes_count', 0)),
    eventsCount: Number(readField(raw, 'eventsCount', 'events_count', 0)),
    topProcesses: readField(raw, 'topProcesses', 'top_processes', []),
    networkConnections: readField(raw, 'networkConnections', 'network_connections', []),
    fileEvents: readField(raw, 'fileEvents', 'file_events', []),
    securityFindings: readField(raw, 'securityFindings', 'security_findings', []),
  };
}

function runCommand(command: string, timeout = 10000): Promise<string> {
  return execAsync(command, { timeout, windowsHide: true })
    .then(({ stdout }) => stdout)
    .catch(() => '');
}

function normalizeMac(mac: string): string {
  return mac.replace(/-/g, ':').toUpperCase();
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function triggerSubnetPingSweep(subnetPrefix: string): Promise<void> {
  const pingCommands = Array.from({ length: 254 }, (_, idx) => {
    const ip = `${subnetPrefix}.${idx + 1}`;
    const cmd = isWindows ? `ping -n 1 -w 250 ${ip}` : `ping -c 1 -W 1 ${ip}`;
    return runCommand(cmd, 1500);
  });

  for (let i = 0; i < pingCommands.length; i += 64) {
    await Promise.all(pingCommands.slice(i, i + 64));
  }
}

async function getRealArpDevices(targetSubnet: string): Promise<Array<{ ip: string; mac: string }>> {
  const outputs = await Promise.all([
    runCommand('arp -a'),
    isWindows ? Promise.resolve('') : runCommand('ip neigh show'),
  ]);
  const found = new Map<string, string>();
  const macRegex = /(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}/i;
  const ipRegex = new RegExp(`\\b${escapeRegex(targetSubnet)}\\.\\d{1,3}\\b`);

  for (const output of outputs) {
    for (const line of output.split('\n')) {
      const ip = line.match(ipRegex)?.[0];
      const mac = line.match(macRegex)?.[0];
      if (ip && mac && !/^ff[:-]ff[:-]ff[:-]ff[:-]ff[:-]ff$/i.test(mac)) {
        found.set(ip, normalizeMac(mac));
      }
    }
  }

  return Array.from(found, ([ip, mac]) => ({ ip, mac }));
}

// Real Socket Connection Probe
function checkPort(host: string, port: number, timeoutMs = 120): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(timeoutMs);
    socket.on('connect', () => {
      socket.destroy();
      resolve(true);
    });
    socket.on('timeout', () => {
      socket.destroy();
      resolve(false);
    });
    socket.on('error', () => {
      socket.destroy();
      resolve(false);
    });
    socket.connect(port, host);
  });
}

// ═══════════════════════════════════════════════════════════════════════════
// Real-Time MITRE ATT&CK Deep Telemetry Correlation Engine v2.0
// 19 rules — Process, Network, File, Behavior correlation
// ═══════════════════════════════════════════════════════════════════════════

function generateAlertId(): string {
  return `alert-${Date.now()}-${Math.floor(Math.random() * 9999)}`;
}

async function fireAlert(agent: AgentRecord, ruleId: string, ruleName: string, severity: EDRAlert['severity'], details: string) {
  const alert: EDRAlert = {
    alertId: generateAlertId(),
    agentId: agent.agentId,
    hostname: agent.hostname,
    ruleId, ruleName, severity,
    timestamp: new Date().toISOString(),
    details,
    status: 'ACTIVE'
  };
  alertsHistory.unshift(alert);
  if (alertsHistory.length > 500) alertsHistory.length = 500;
  await saveAlertToDb(alert);
  broadcastSSE('alert', alert);
  console.log(`🚨 [DETECTION] ${severity} | ${ruleName} | ${agent.hostname} | ${details.substring(0, 120)}`);
}

// Known Windows system binaries and their expected paths
const SYSTEM_BINARIES: Record<string, string[]> = {
  'svchost.exe': ['c:\\windows\\system32\\svchost.exe', 'c:\\windows\\syswow64\\svchost.exe'],
  'csrss.exe': ['c:\\windows\\system32\\csrss.exe'],
  'lsass.exe': ['c:\\windows\\system32\\lsass.exe'],
  'services.exe': ['c:\\windows\\system32\\services.exe'],
  'winlogon.exe': ['c:\\windows\\system32\\winlogon.exe'],
  'smss.exe': ['c:\\windows\\system32\\smss.exe'],
  'wininit.exe': ['c:\\windows\\system32\\wininit.exe'],
  'dwm.exe': ['c:\\windows\\system32\\dwm.exe'],
};

const LOLBINS = new Set([
  'certutil.exe', 'mshta.exe', 'regsvr32.exe', 'rundll32.exe',
  'bitsadmin.exe', 'wscript.exe', 'cscript.exe', 'msiexec.exe',
  'installutil.exe', 'regasm.exe', 'regsvcs.exe', 'msxsl.exe',
  'control.exe', 'presentationhost.exe', 'bash.exe',
]);

const OFFICE_PROCESSES = new Set(['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'msaccess.exe', 'mspub.exe']);
const SHELL_PROCESSES = new Set(['cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe', 'bash.exe', 'mshta.exe']);
const KNOWN_SYSTEM_PROCS = new Set(['system', 'idle', 'svchost.exe', 'csrss.exe', 'dwm.exe', 'lsass.exe', 'services.exe', 'wininit.exe', 'winlogon.exe', 'smss.exe', 'taskhostw.exe', 'runtimebroker.exe', 'explorer.exe', 'searchhost.exe', 'sihost.exe', 'ctfmon.exe']);
const LATERAL_PORTS = new Set([445, 3389, 5985, 5986, 22, 23, 135, 139]);
const SUSPICIOUS_C2_PORTS = new Set([4444, 6667, 1337, 8888, 31337, 9999, 1234, 5555, 7777, 13337]);

async function evaluateATTACKRules(agent: AgentRecord, payload: TelemetryPayload) {
  const procs = payload.topProcesses || [];
  const conns = payload.networkConnections || [];
  const files = payload.fileEvents || [];
  const findings = payload.securityFindings || [];

  // Build PID -> Process map for parent-child analysis
  const pidMap = new Map<number, ProcessTelemetry>();
  for (const p of procs) { pidMap.set(p.pid, p); }

  // ═══ 1. PowerShell Encoded Command [T1059.001] ═══
  for (const proc of procs) {
    const name = proc.name.toLowerCase();
    const exe = proc.executablePath.toLowerCase();
    if ((name.includes('powershell') || name.includes('pwsh')) && 
        (exe.includes('-enc') || exe.includes('encodedcommand') || exe.includes('base64') || exe.includes('-nop') || exe.includes('bypass'))) {
      await fireAlert(agent, 'RULE-WIN-001', 'PowerShell Encoded Command Execution', 'HIGH',
        `PID ${proc.pid} (${proc.name}) executou payload PowerShell codificado. Path: ${proc.executablePath}`);
    }
  }

  // ═══ 2. LSASS Credential Dump [T1003.001] ═══
  for (const proc of procs) {
    if (proc.name.toLowerCase() === 'lsass.exe' && proc.cpuPct > 25) {
      await fireAlert(agent, 'RULE-MEM-005', 'LSASS Memory Credential Dumping Attempt', 'CRITICAL',
        `Acesso anômalo ao processo LSASS detectado — PID ${proc.pid}, CPU: ${proc.cpuPct.toFixed(1)}%`);
    }
  }

  // ═══ 3. Suspicious C2 Ports [T1071] ═══
  for (const conn of conns) {
    if (SUSPICIOUS_C2_PORTS.has(conn.remotePort) && conn.status === 'ESTABLISHED') {
      await fireAlert(agent, 'RULE-NET-003', 'Suspicious Remote Port Outbound Socket', 'HIGH',
        `PID ${conn.pid} (${conn.processName}) conectou à porta suspeita ${conn.remotePort} em ${conn.remoteAddress}`);
    }
  }

  // ═══ 4. Ransomware File Extensions [T1486] ═══
  const ransomExts = ['.locked', '.crypto', '.enc', '.ransom', '.crypt', '.cerber', '.locky', '.wncry', '.wncryt', '.wcry'];
  for (const fileEvt of files) {
    const p = fileEvt.filePath.toLowerCase();
    if (ransomExts.some(ext => p.endsWith(ext))) {
      await fireAlert(agent, 'RULE-FILE-002', 'Ransomware Mass File Alteration Spike', 'CRITICAL',
        `Extensão ransomware detectada: ${fileEvt.filePath}`);
    }
  }

  // ═══ 5. Process Masquerading [T1036.005] ═══
  for (const proc of procs) {
    const name = proc.name.toLowerCase();
    const exe = proc.executablePath.toLowerCase().replace(/\//g, '\\');
    if (SYSTEM_BINARIES[name]) {
      const expected = SYSTEM_BINARIES[name];
      if (exe && !expected.some(ep => exe === ep || exe.endsWith('\\' + name))) {
        await fireAlert(agent, 'RULE-MASQ-012', 'System Binary Path Masquerading', 'CRITICAL',
          `${proc.name} executando de caminho inesperado: "${proc.executablePath}" (esperado: ${expected[0]})`);
      }
    }
  }

  // ═══ 6. Suspicious Parent-Child Chains [T1059] ═══
  for (const proc of procs) {
    const name = proc.name.toLowerCase();
    const parentPid = proc.parentPid;
    if (parentPid != null && SHELL_PROCESSES.has(name)) {
      const parent = pidMap.get(parentPid);
      if (parent && OFFICE_PROCESSES.has(parent.name.toLowerCase())) {
        await fireAlert(agent, 'RULE-CHAIN-013', 'Suspicious Parent-Child Process Chain', 'HIGH',
          `Aplicação Office "${parent.name}" (PID ${parent.pid}) gerou shell "${proc.name}" (PID ${proc.pid}) — possível macro maliciosa`);
      }
    }
    // svchost.exe should have services.exe as parent
    if (name === 'svchost.exe' && parentPid != null) {
      const parent = pidMap.get(parentPid);
      if (parent && parent.name.toLowerCase() !== 'services.exe') {
        await fireAlert(agent, 'RULE-CHAIN-013', 'Suspicious Parent-Child Process Chain', 'CRITICAL',
          `svchost.exe (PID ${proc.pid}) com pai inesperado: "${parent.name}" (PID ${parent.pid}) — deveria ser services.exe`);
      }
    }
  }

  // ═══ 7. LOLBin Execution [T1218] ═══
  for (const proc of procs) {
    if (LOLBINS.has(proc.name.toLowerCase())) {
      await fireAlert(agent, 'RULE-LOL-014', 'Living-off-the-Land Binary Execution', 'HIGH',
        `LOLBin detectado em execução: ${proc.name} (PID ${proc.pid}) — Path: ${proc.executablePath}`);
    }
  }

  // ═══ 8. C2 Beaconing Detection [T1071.001] ═══
  const currentTargets = new Map<string, number>();
  for (const conn of conns) {
    if (conn.status === 'ESTABLISHED' && conn.remoteAddress && conn.remotePort > 0) {
      const key = `${conn.remoteAddress}:${conn.remotePort}`;
      currentTargets.set(key, (currentTargets.get(key) || 0) + 1);
    }
  }
  let history = agentTelemetryHistory.get(agent.agentId);
  if (!history) {
    history = { prevConnectionCount: 0, prevTimestamp: Date.now(), connectionTargets: new Map() };
    agentTelemetryHistory.set(agent.agentId, history);
  }
  for (const [target, _count] of currentTargets) {
    const prevCount = history.connectionTargets.get(target) || 0;
    const consecutive = prevCount + 1;
    history.connectionTargets.set(target, consecutive);
    // If same target appears in 3+ consecutive heartbeats, flag as beaconing
    if (consecutive >= 3) {
      await fireAlert(agent, 'RULE-BEACON-015', 'C2 Beaconing Regular Interval Detection', 'CRITICAL',
        `Conexão persistente para ${target} detectada em ${consecutive} heartbeats consecutivos — possível C2 beaconing`);
      history.connectionTargets.set(target, 0); // Reset to avoid alert spam
    }
  }
  // Clear targets no longer present
  for (const [target] of history.connectionTargets) {
    if (!currentTargets.has(target)) history.connectionTargets.delete(target);
  }

  // ═══ 9. Data Exfiltration Volume Spike [T1041] ═══
  const currentConnCount = conns.filter(c => c.status === 'ESTABLISHED').length;
  if (history.prevConnectionCount > 0 && currentConnCount > history.prevConnectionCount * 3 && currentConnCount > 10) {
    await fireAlert(agent, 'RULE-EXFIL-016', 'Data Exfiltration Connection Volume Spike', 'HIGH',
      `Spike de conexões: ${history.prevConnectionCount} → ${currentConnCount} (${(currentConnCount / history.prevConnectionCount).toFixed(1)}x) — possível exfiltração`);
  }
  history.prevConnectionCount = currentConnCount;
  history.prevTimestamp = Date.now();

  // ═══ 10. Cryptominer Detection [T1496] ═══
  if (payload.cpuUsagePct > 85) {
    const topProc = [...procs].sort((a, b) => b.cpuPct - a.cpuPct)[0];
    if (topProc && !KNOWN_SYSTEM_PROCS.has(topProc.name.toLowerCase())) {
      await fireAlert(agent, 'RULE-MINER-017', 'Cryptominer High CPU Anomaly', 'HIGH',
        `CPU do endpoint em ${payload.cpuUsagePct.toFixed(1)}% — processo principal: ${topProc.name} (PID ${topProc.pid}, CPU: ${topProc.cpuPct.toFixed(1)}%)`);
    }
  }

  // ═══ 11. Resource Exhaustion [T1499] ═══
  if (payload.cpuUsagePct > 85 || payload.memoryUsagePct > 90) {
    await fireAlert(agent, 'RULE-RES-004', 'Endpoint High Resource Exhaustion Spike', 'WARNING',
      `Recursos críticos: CPU ${payload.cpuUsagePct.toFixed(1)}% | RAM ${payload.memoryUsagePct.toFixed(1)}%`);
  }

  // ═══ 12. DNS Tunneling [T1071.004] ═══
  const dnsConns = conns.filter(c => c.remotePort === 53 && c.protocol.toUpperCase().includes('UDP'));
  if (dnsConns.length > 10) {
    await fireAlert(agent, 'RULE-NET-008', 'DNS Tunneling High Frequency Query Exfiltration', 'HIGH',
      `${dnsConns.length} conexões DNS UDP detectadas neste heartbeat — possível túnel DNS para exfiltração`);
  }

  // ═══ 13. Lateral Movement [T1021] ═══
  for (const conn of conns) {
    if (LATERAL_PORTS.has(conn.remotePort) && conn.status === 'ESTABLISHED') {
      const procName = conn.processName.toLowerCase();
      // Skip expected admin tools
      if (!['svchost.exe', 'services.exe', 'system', 'lsass.exe'].includes(procName)) {
        await fireAlert(agent, 'RULE-LATERAL-018', 'Lateral Movement Outbound Connection', 'HIGH',
          `Processo "${conn.processName}" (PID ${conn.pid}) conectou à porta lateral ${conn.remotePort} em ${conn.remoteAddress}`);
      }
    }
  }

  // ═══ 14. WMI Execution [T1047] ═══
  for (const proc of procs) {
    if (proc.name.toLowerCase() === 'wmic.exe' || proc.name.toLowerCase() === 'wmiprvse.exe') {
      await fireAlert(agent, 'RULE-CMD-009', 'WMI Administrative Command Line Execution', 'INFO',
        `Processo WMI detectado: ${proc.name} (PID ${proc.pid}) — Path: ${proc.executablePath}`);
    }
  }

  // ═══ 15. System32 File Alteration [T1554] ═══
  for (const fileEvt of files) {
    const fp = fileEvt.filePath.toLowerCase().replace(/\//g, '\\');
    if ((fp.includes('\\windows\\system32\\') || fp.includes('\\windows\\syswow64\\')) &&
        (fileEvt.action === 'MODIFIED' || fileEvt.action === 'CREATED' || fileEvt.action === 'DELETED')) {
      await fireAlert(agent, 'RULE-SYS-007', 'Unauthorized System File Alteration in System32', 'HIGH',
        `Alteração em arquivo do sistema: ${fileEvt.filePath} (${fileEvt.action})`);
    }
  }

  // ═══ 16. Agent Security Findings Escalation ═══
  for (const finding of findings) {
    if (finding.severity === 'HIGH' || finding.severity === 'CRITICAL') {
      await fireAlert(agent, 'RULE-FINDING-019', `Agent Finding: ${finding.findingType}`, finding.severity as EDRAlert['severity'],
        `[${finding.mitreId}] ${finding.description} | Evidência: ${finding.evidence}`);
    }
  }

  // ═══ 17. YARA Signature Matching ═══
  for (const fileEvt of files) {
    if (fileEvt.yaraMatches && fileEvt.yaraMatches.length > 0) {
      for (const matchName of fileEvt.yaraMatches) {
        await fireAlert(agent, 'RULE-YARA-020', 'YARA Signature Match Detection', 'CRITICAL',
          `Assinatura YARA "${matchName}" detectada no arquivo: ${fileEvt.filePath}`);
      }
    }
    // Also evaluate built-in YARA strings on executable path / filenames
    const fpath = fileEvt.filePath.toLowerCase();
    for (const rule of builtInYaraRules) {
      for (const str of rule.strings) {
        if (fpath.includes(str.toLowerCase())) {
          await fireAlert(agent, 'RULE-YARA-020', `YARA: ${rule.name}`, rule.severity,
            `[${rule.mitreId}] Padrão YARA "${str}" detectado no arquivo: ${fileEvt.filePath}`);
        }
      }
    }
  }

  // Also check top process commandlines against YARA strings
  for (const proc of procs) {
    const exe = proc.executablePath.toLowerCase();
    for (const rule of builtInYaraRules) {
      for (const str of rule.strings) {
        if (exe.includes(str.toLowerCase())) {
          await fireAlert(agent, 'RULE-YARA-020', `YARA: ${rule.name}`, rule.severity,
            `[${rule.mitreId}] Padrão YARA "${str}" detectado na linha de comando do processo ${proc.name} (PID ${proc.pid})`);
        }
      }
    }
  }
}

// Deep Multi-Protocol Device Recognition Engine
async function performDeepNetworkDiscovery(targetSubnet: string): Promise<DiscoveredDevice[]> {
  console.log(`📡 Executing DEEP Multi-Protocol Network Discovery on ${targetSubnet}.0/24...`);
  
  // First trigger fast ICMP ping sweep to populate Windows ARP table
  await triggerSubnetPingSweep(targetSubnet);
  
  // Read Windows Kernel ARP table
  const arpNeighbors = await getRealArpDevices(targetSubnet);
  const probePorts = [21, 22, 23, 80, 135, 137, 139, 443, 445, 548, 631, 1900, 3306, 3389, 5353, 8080];

  const targetIPs = new Set<string>();
  for (const n of arpNeighbors) {
    targetIPs.add(n.ip);
  }
  for (const agent of agents.values()) {
    if (agent.inventory.ipAddress?.startsWith(`${targetSubnet}.`)) {
      targetIPs.add(agent.inventory.ipAddress);
    }
  }
  if (targetIPs.size === 0) {
    targetIPs.add(`${targetSubnet}.1`);
  }

  const probePromises = Array.from(targetIPs).map(async (targetIp) => {
    const openPorts: number[] = [];
    for (const p of probePorts) {
      const isOpen = await checkPort(targetIp, p, 100);
      if (isOpen) openPorts.push(p);
    }

    const arpEntry = arpNeighbors.find((a) => a.ip === targetIp);
    const mac = arpEntry ? arpEntry.mac : '00:00:00:00:00:00';
    const lastOctet = parseInt(targetIp.split('.')[3] || '0', 10);

    const threats: string[] = [];
    let risk: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';

    if (openPorts.includes(23)) {
      threats.push('Porta Telnet 23 Exposta (Vulnerável a Interceptação e Botnet)');
      risk = 'CRITICAL';
    }
    if (openPorts.includes(445)) {
      threats.push('Porta SMB 445 Aberta (Vulnerabilidade Potencial Windows / Worms)');
      if (risk !== 'CRITICAL') risk = 'HIGH';
    }
    if (openPorts.includes(3389)) {
      threats.push('Porta RDP 3389 Exposta sem Firewall');
      if (risk === 'LOW') risk = 'MEDIUM';
    }
    if (openPorts.includes(21)) {
      threats.push('Porta FTP 21 Não Criptografada');
      if (risk === 'LOW') risk = 'MEDIUM';
    }

    // Dynamic Device Type & Vendor Classification
    let deviceType: 'ROUTER' | 'WINDOWS' | 'LINUX' | 'PRINTER' | 'IOT' = 'IOT';
    let vendorName = `Dispositivo Conectado (${targetIp})`;

    if (lastOctet === 1 || openPorts.includes(53)) {
      deviceType = 'ROUTER';
      vendorName = `Gateway Roteador / Access Point (${targetIp})`;
    } else if (openPorts.includes(631)) {
      deviceType = 'PRINTER';
      vendorName = `Impressora de Rede IPP (${targetIp})`;
    } else if (openPorts.includes(135) || openPorts.includes(445) || openPorts.includes(139)) {
      deviceType = 'WINDOWS';
      vendorName = `Estação Windows da Rede (${targetIp})`;
    } else if (openPorts.includes(22)) {
      deviceType = 'LINUX';
      vendorName = `Servidor Linux / Device SSH (${targetIp})`;
    } else if (openPorts.includes(548) || openPorts.includes(5353)) {
      deviceType = 'IOT';
      vendorName = `Dispositivo Apple / Smart TV (${targetIp})`;
    } else if (openPorts.includes(1900) || openPorts.includes(8080)) {
      deviceType = 'IOT';
      vendorName = `Smart TV / Chromecast / IoT (${targetIp})`;
    }

    return {
      ipAddress: targetIp,
      macAddress: mac,
      vendorName,
      deviceType,
      openPorts,
      riskScore: risk,
      detectedThreats: threats,
      lastSeen: new Date().toISOString(),
    };
  });

  const results = await Promise.all(probePromises);
  const discovered: DiscoveredDevice[] = [];
  for (const item of results) {
    if (item) discovered.push(item);
  }

  discoveredDevices = discovered;
  await saveDiscoveredDevicesToDb(discoveredDevices);
  broadcastSSE('network_scan_complete', discoveredDevices);
  return discovered;
}

// POST /api/v1/network/scan (Deep Network Discovery Engine)
app.post('/api/v1/network/scan', async (req: Request, res: Response) => {
  try {
    const detectedSubnets = getLocalSubnets();
    const targetSubnet = req.body.subnet || detectedSubnets[0] || '192.168.50';

    const devices = await performDeepNetworkDiscovery(targetSubnet);

    res.json({
      scanId: `scan-${Date.now()}`,
      subnet: `${targetSubnet}.0/24`,
      scannedAt: new Date().toISOString(),
      totalDiscovered: devices.length,
      devices,
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to perform network scan' });
  }
});

// GET /api/v1/network/scan/latest
app.get('/api/v1/network/scan/latest', async (_req: Request, res: Response) => {
  try {
    if (discoveredDevices.length === 0) {
      discoveredDevices = await loadDiscoveredDevicesFromDb();
    }
    if (discoveredDevices.length === 0) {
      const detectedSubnets = getLocalSubnets();
      await performDeepNetworkDiscovery(detectedSubnets[0] || '192.168.50');
    }
    res.json(discoveredDevices);
  } catch (error) {
    res.status(500).json({ error: 'Failed to retrieve latest network scan' });
  }
});

// Helper to resolve guardian_termux_agent.py dynamically regardless of working directory
function findAgentPyPath(): string | null {
  const candidates = [
    path.join(process.cwd(), 'guardian-agent', 'guardian_termux_agent.py'),
    path.join(process.cwd(), '..', 'guardian-agent', 'guardian_termux_agent.py'),
    path.resolve('..', 'guardian-agent', 'guardian_termux_agent.py'),
    path.resolve('guardian-agent', 'guardian_termux_agent.py'),
    path.join(__dirname, '..', 'public', 'agent.py'),
    path.join(process.cwd(), 'public', 'agent.py'),
    path.join(__dirname, '..', '..', 'guardian-agent', 'guardian_termux_agent.py'),
    path.join(__dirname, '..', 'guardian-agent', 'guardian_termux_agent.py'),
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }
  return null;
}

function findInstallShPath(): string | null {
  const candidates = [
    path.join(process.cwd(), 'guardian-agent', 'install-android.sh'),
    path.join(process.cwd(), '..', 'guardian-agent', 'install-android.sh'),
    path.resolve('..', 'guardian-agent', 'install-android.sh'),
    path.resolve('guardian-agent', 'install-android.sh'),
    path.join(__dirname, '..', 'public', 'install-android.sh'),
    path.join(__dirname, '..', '..', 'guardian-agent', 'install-android.sh'),
    path.join(__dirname, '..', 'guardian-agent', 'install-android.sh'),
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }
  return null;
}

// GET /download/install.sh (Dynamic Installer Endpoint for Android / Termux)
const handleInstallScriptDownload = (req: Request, res: Response) => {
  const installPath = findInstallShPath();
  if (installPath && fs.existsSync(installPath)) {
    let scriptContent = fs.readFileSync(installPath, 'utf-8');
    const protocol = req.protocol || 'http';
    const host = req.headers.host || `localhost:${PORT}`;
    const serverUrl = `${protocol}://${host}`;
    scriptContent = scriptContent
      .replace(/\r\n?/g, '\n')
      .replace(/http:\/\/192\.168\.50\.140:4000/g, serverUrl);

    res.setHeader('Content-Type', 'text/x-shellscript; charset=utf-8');
    res.send(scriptContent);
  } else {
    res.status(404).send('Install script file not found on server');
  }
};

// GET /download/agent.py (Direct HTTP Download Endpoint for Android Phones / Termux)
const handleAgentDownload = (_req: Request, res: Response) => {
  const agentPath = findAgentPyPath();
  if (agentPath && fs.existsSync(agentPath)) {
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="agent.py"');
    res.sendFile(path.resolve(agentPath), (err) => {
      if (err && !res.headersSent) {
        res.status(500).json({ error: 'Failed to send agent file' });
      }
    });
  } else {
    res.status(404).send('Agent script file not found on server');
  }
};

app.get('/download/agent.py', handleAgentDownload);
app.get('/download/agent', handleAgentDownload);
app.get('/agent.py', handleAgentDownload);

app.get('/download/install.sh', handleInstallScriptDownload);
app.get('/download/android.sh', handleInstallScriptDownload);
app.get('/download/install', handleInstallScriptDownload);
app.get('/download/android', handleInstallScriptDownload);
app.get('/install.sh', handleInstallScriptDownload);
app.get('/android.sh', handleInstallScriptDownload);
app.get('/install', handleInstallScriptDownload);
app.get('/android', handleInstallScriptDownload);



// GET /api/v1/stream (Server-Sent Events Real-Time Live Feed)
app.get('/api/v1/stream', (req: Request, res: Response) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  sseClients.push(res);

  req.on('close', () => {
    sseClients = sseClients.filter((client) => client !== res);
  });
});

// GET /api/v1/health
app.get('/api/v1/health', (_req: Request, res: Response) => {
  res.json({ 
    status: 'ok', 
    service: 'Guardian Core Server', 
    detectedSubnets: getLocalSubnets(),
    databaseConnected: isDbConnected(),
    agentlessScannerActive: true,
    rulesCount: activeRules.length,
    timestamp: new Date().toISOString() 
  });
});

// GET /api/v1/stats
app.get('/api/v1/stats', (_req: Request, res: Response) => {
  const allAgents = Array.from(agents.values());
  const total = allAgents.length;
  const online = allAgents.filter((a) => a.status === 'online').length;
  const activeAlerts = alertsHistory.filter((a) => a.status === 'ACTIVE').length;

  res.json({
    totalAgents: total,
    onlineAgents: online,
    activeAlertsCount: activeAlerts,
    agentlessDiscoveredDevices: discoveredDevices.length,
    detectedSubnets: getLocalSubnets(),
    agentlessScannerActive: true,
    databaseConnected: isDbConnected(),
  });
});

// GET /api/v1/agents
app.get('/api/v1/agents', (_req: Request, res: Response) => {
  const now = Date.now();
  const agentList: AgentRecord[] = [];
  for (const ag of agents.values()) {
    const lastHbMs = new Date(ag.lastHeartbeat).getTime();
    const isStale = (now - lastHbMs) > 20000; // >20s without heartbeat
    const copy: AgentRecord = {
      ...ag,
      status: ag.status === 'isolated' ? 'isolated' : isStale ? 'offline' : ag.status
    };
    if (isStale && ag.status !== 'isolated') {
      copy.topProcesses = [];
      copy.networkConnections = [];
      copy.fileEvents = [];
    }
    agentList.push(copy);
  }
  res.json(agentList);
});

// GET /api/v1/processes (ONLY LIVE ONLINE AGENTS)
app.get('/api/v1/processes', (_req: Request, res: Response) => {
  const now = Date.now();
  const allProcesses: Array<ProcessTelemetry & { hostname: string; agentId: string }> = [];
  for (const agent of agents.values()) {
    const lastHbMs = new Date(agent.lastHeartbeat).getTime();
    const isOnline = (now - lastHbMs) <= 20000;
    if (isOnline && agent.status !== 'isolated' && agent.topProcesses) {
      for (const proc of agent.topProcesses) {
        allProcesses.push({
          ...proc,
          hostname: agent.hostname,
          agentId: agent.agentId,
        });
      }
    }
  }
  res.json(allProcesses);
});

// GET /api/v1/network (ONLY LIVE ONLINE AGENTS)
app.get('/api/v1/network', (_req: Request, res: Response) => {
  const now = Date.now();
  const allConnections: Array<NetworkTelemetry & { hostname: string; agentId: string }> = [];
  for (const agent of agents.values()) {
    const lastHbMs = new Date(agent.lastHeartbeat).getTime();
    const isOnline = (now - lastHbMs) <= 20000;
    if (isOnline && agent.status !== 'isolated' && agent.networkConnections) {
      for (const conn of agent.networkConnections) {
        allConnections.push({
          ...conn,
          hostname: agent.hostname,
          agentId: agent.agentId,
        });
      }
    }
  }
  res.json(allConnections);
});

// GET /api/v1/files (ONLY LIVE ONLINE AGENTS)
app.get('/api/v1/files', (_req: Request, res: Response) => {
  const now = Date.now();
  const allFiles: Array<FileTelemetry & { hostname: string; agentId: string }> = [];
  for (const agent of agents.values()) {
    const lastHbMs = new Date(agent.lastHeartbeat).getTime();
    const isOnline = (now - lastHbMs) <= 20000;
    if (isOnline && agent.status !== 'isolated' && agent.fileEvents) {
      for (const fileEvt of agent.fileEvents) {
        allFiles.push({
          ...fileEvt,
          hostname: agent.hostname,
          agentId: agent.agentId,
        });
      }
    }
  }
  res.json(allFiles);
});

// GET /api/v1/rules
app.get('/api/v1/rules', (_req: Request, res: Response) => {
  res.json(activeRules);
});

// GET /api/v1/yara/rules
app.get('/api/v1/yara/rules', (_req: Request, res: Response) => {
  res.json(builtInYaraRules);
});

// GET /api/v1/alerts
app.get('/api/v1/alerts', (_req: Request, res: Response) => {
  res.json(alertsHistory);
});

// POST /api/v1/rules/create
app.post('/api/v1/rules/create', (req: Request, res: Response) => {
  const newRule: RuleDefinition = req.body;
  if (!newRule.ruleId || !newRule.name) {
    return res.status(400).json({ error: 'ruleId and name are required' });
  }
  activeRules.unshift(newRule);
  res.status(201).json({ status: 'created', rule: newRule });
});

// DELETE /api/v1/agents/:agentId (Remove Agent from DB and Memory)
app.delete('/api/v1/agents/:agentId', async (req: Request, res: Response) => {
  const { agentId } = req.params;
  console.log(`🗑️ Deleting agent ${agentId} from memory and SQL database...`);
  
  agents.delete(agentId);
  await deleteAgentFromDb(agentId);
  broadcastSSE('agent_deleted', { agentId });
  
  res.json({ status: 'deleted', agentId });
});

// POST /api/v1/response/kill
app.post('/api/v1/response/kill', (req: Request, res: Response) => {
  const { agentId, pid } = req.body;
  console.log(`☠️ Execution response kill sent for process PID ${pid} on agent ${agentId}`);
  res.json({ status: 'sent', agentId, pid });
});

// POST /api/v1/response/isolate
app.post('/api/v1/response/isolate', async (req: Request, res: Response) => {
  const { agentId } = req.body;
  const agent = agents.get(agentId);
  if (agent) {
    agent.status = 'isolated';
    await saveAgentToDb(agent);
  }
  console.log(`🔒 Network isolation command sent to agent ${agentId}`);
  res.json({ status: 'isolated', agentId });
});

// POST /api/v1/agents/register (Protected by verifyAgentToken & DEDUPLICATED BY HOSTNAME)
app.post('/api/v1/agents/register', verifyAgentToken, async (req: Request, res: Response) => {
  const inventory: SystemInventory = normalizeInventory(req.body);
  if (!inventory.hostname) {
    return res.status(400).json({ error: 'Hostname is required' });
  }

  let existingAgentKey: string | null = null;
  for (const [key, agent] of agents.entries()) {
    if (agent.hostname.toLowerCase() === inventory.hostname.toLowerCase()) {
      existingAgentKey = key;
      break;
    }
  }

  const agentId = existingAgentKey || `agent-${inventory.hostname.toLowerCase()}`;
  const updatedAgent: AgentRecord = {
    agentId,
    hostname: inventory.hostname,
    status: 'online',
    inventory,
    lastHeartbeat: new Date().toISOString(),
    metrics: {
      cpuUsagePct: 0,
      memoryUsagePct: 0,
      diskUsagePct: 0,
      activeProcessesCount: 0,
    },
    topProcesses: [],
    networkConnections: [],
    fileEvents: [],
  };

  agents.set(agentId, updatedAgent);
  await saveAgentToDb(updatedAgent);
  broadcastSSE('agent_registered', updatedAgent);

  res.status(201).json({ agentId, status: 'registered', expectedPayloadCase: 'camelCase_or_snake_case' });
});

// POST /api/v1/agents/heartbeat (Protected by verifyAgentToken & EVALUATES MITRE ATT&CK RULES)
app.post('/api/v1/agents/heartbeat', verifyAgentToken, async (req: Request, res: Response) => {
  const payload: TelemetryPayload = normalizeTelemetry(req.body);
  
  let agent = agents.get(payload.agentId);
  if (!agent) {
    for (const a of agents.values()) {
      if (a.agentId === payload.agentId || a.hostname === payload.agentId) {
        agent = a;
        break;
      }
    }
  }

  if (!agent) {
    console.warn(`⚠️ Heartbeat from unregistered agent: ${payload.agentId}`);
    return res.status(404).json({ error: 'Agent not registered' });
  }

  agent.lastHeartbeat = new Date().toISOString();
  if (agent.status !== 'isolated') {
    agent.status = payload.cpuUsagePct > 85 || payload.memoryUsagePct > 90 ? 'warning' : 'online';
  }
  agent.metrics = {
    cpuUsagePct: payload.cpuUsagePct,
    memoryUsagePct: payload.memoryUsagePct,
    diskUsagePct: payload.diskUsagePct,
    activeProcessesCount: payload.activeProcessesCount,
  };
  agent.topProcesses = payload.topProcesses || [];
  agent.networkConnections = payload.networkConnections || [];
  agent.fileEvents = payload.fileEvents || [];

  // Evaluate Telemetry against Real-Time ATT&CK Correlation Engine
  await evaluateATTACKRules(agent, payload);

  // Save to SQLite Database Tables
  await saveAgentToDb(agent);
  await saveTelemetryToDb(agent.agentId, agent.topProcesses || [], agent.networkConnections || [], agent.fileEvents || []);
  broadcastSSE('telemetry', { agentId: agent.agentId, hostname: agent.hostname });

  console.log(`📥 [HEARTBEAT & CORRELATION EVALUATED] ${agent.hostname} | CPU: ${payload.cpuUsagePct.toFixed(1)}% | Procs: ${(payload.topProcesses || []).length} | Net: ${(payload.networkConnections || []).length}`);

  res.json({ status: 'acknowledged', nextHeartbeatIntervalSec: 30 });
});

// Start DB Initialization & Server Listen & Deep Discovery on ALL physical subnets
initDatabase().then(async () => {
  // Load initial SQL data
  const dbAgents = await loadAgentsFromDb();
  for (const ag of dbAgents) {
    agents.set(ag.agentId, ag);
  }
  discoveredDevices = await loadDiscoveredDevicesFromDb();

  // Background Live Agent Lifecycle & Cleanup Loop (runs every 10s)
  setInterval(async () => {
    const now = Date.now();
    for (const [agentId, agent] of agents.entries()) {
      const lastHbMs = new Date(agent.lastHeartbeat).getTime();
      const elapsed = now - lastHbMs;

      if (elapsed > 20000 && (agent.status === 'online' || agent.status === 'warning')) {
        agent.status = 'offline';
        agent.topProcesses = [];
        agent.networkConnections = [];
        agent.fileEvents = [];
        await saveAgentToDb(agent);
        broadcastSSE('agent_updated', agent);
        console.log(`⚠️ Agente ${agent.hostname} (${agentId}) marcado como OFFLINE por timeout de heartbeat (${Math.round(elapsed / 1000)}s sem comunicação)`);
      }
    }
  }, 10000);

  app.listen(Number(PORT), '0.0.0.0', async () => {
    const detectedSubnets = getLocalSubnets();
    console.log(`🛡️ Guardian Core API Server running on 0.0.0.0:${PORT} [MITRE ATT&CK Engine Active]`);

    console.log(`📡 Detected subnets (priority order): ${detectedSubnets.join(', ')}`);
    
    // Scan ALL physical subnets on startup to find all devices
    for (const subnet of detectedSubnets) {
      if (subnet.startsWith('172.')) continue;
      console.log(`🔍 Starting deep discovery on ${subnet}.0/24...`);
      const devices = await performDeepNetworkDiscovery(subnet);
      console.log(`✅ Found ${devices.length} devices on ${subnet}.0/24`);
    }
  });
});
