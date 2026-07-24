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
  SystemInventory, 
  TelemetryPayload 
} from './types.js';
import { 
  initDatabase, 
  isDbConnected, 
  saveAgentToDb, 
  saveAlertToDb, 
  saveTelemetryToDb 
} from './db.js';

const app = express();
const PORT = process.env.PORT || 4000;
const STORAGE_FILE = path.join(process.cwd(), 'storage.json');
const VALID_AGENT_TOKEN = 'GUARDIAN-SECRET-AGENT-KEY-v0.9';
const execAsync = promisify(exec);
const isWindows = process.platform === 'win32';

app.use(cors());
app.use(express.json());

// State Holders
let agents = new Map<string, AgentRecord>();
let eventsHistory: EDREvent[] = [];
let alertsHistory: EDRAlert[] = [];
let quarantineHistory: QuarantineRecord[] = [];
let discoveredDevices: DiscoveredDevice[] = [];
let sseClients: Response[] = [];

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
    description: 'Detects outbound connections to non-standard remote ports (ex: 4444, 6667) [MITRE T1071]',
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
    if (a.startsWith('192.168.50')) return -1;
    if (a.startsWith('192.168')) return -1;
    return 1;
  });

  return sorted.length > 0 ? sorted : ['192.168.50'];
}

// Broadcast Real-time Server-Sent Events (SSE)
function broadcastSSE(event: string, data: any) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  sseClients.forEach((res) => res.write(payload));
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

// Load persisted state from disk if exists
function loadStorage() {
  try {
    if (fs.existsSync(STORAGE_FILE)) {
      const raw = fs.readFileSync(STORAGE_FILE, 'utf-8');
      const data = JSON.parse(raw);
      if (data.agents) {
        agents = new Map(Object.entries(data.agents));
      }
      if (data.eventsHistory) eventsHistory = data.eventsHistory;
      if (data.alertsHistory) alertsHistory = data.alertsHistory;
      if (data.quarantineHistory) quarantineHistory = data.quarantineHistory;
      if (data.discoveredDevices) discoveredDevices = data.discoveredDevices;
      if (data.activeRules && data.activeRules.length >= 10) activeRules = data.activeRules;
      console.log(`💾 Local storage file loaded from ${STORAGE_FILE}`);
    }
  } catch (err) {
    console.error('Failed to load persistence file:', err);
  }
}

// Save current state to disk
function saveStorage() {
  try {
    const agentsObj = Object.fromEntries(agents);
    const data = {
      agents: agentsObj,
      eventsHistory: eventsHistory.slice(0, 200),
      alertsHistory: alertsHistory.slice(0, 100),
      quarantineHistory: quarantineHistory.slice(0, 50),
      discoveredDevices,
      activeRules,
    };
    fs.writeFileSync(STORAGE_FILE, JSON.stringify(data, null, 2), 'utf-8');
  } catch (err) {
    console.error('Failed to save persistence file:', err);
  }
}

loadStorage();

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
    const mac = arpEntry ? arpEntry.mac : '00-15-5D-REAL-IP';
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
      vendorName = targetIp.endsWith('.140') ? `Estação Windows Principal (${targetIp})` : `Estação Windows da Rede (${targetIp})`;
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
  saveStorage();
  broadcastSSE('network_scan_complete', discoveredDevices);
  return discovered;
}

// POST /api/v1/network/scan (Deep Network Discovery Engine)
app.post('/api/v1/network/scan', async (req: Request, res: Response) => {
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
});

// GET /api/v1/network/scan/latest
app.get('/api/v1/network/scan/latest', async (_req: Request, res: Response) => {
  if (discoveredDevices.length === 0) {
    const detectedSubnets = getLocalSubnets();
    await performDeepNetworkDiscovery(detectedSubnets[0] || '192.168.50');
  }
  res.json(discoveredDevices);
});

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
  res.json(Array.from(agents.values()));
});

// GET /api/v1/processes
app.get('/api/v1/processes', (_req: Request, res: Response) => {
  const allProcesses: Array<ProcessTelemetry & { hostname: string; agentId: string }> = [];
  for (const agent of agents.values()) {
    if (agent.topProcesses) {
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

// GET /api/v1/network
app.get('/api/v1/network', (_req: Request, res: Response) => {
  const allConnections: Array<NetworkTelemetry & { hostname: string; agentId: string }> = [];
  for (const agent of agents.values()) {
    if (agent.networkConnections) {
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

// GET /api/v1/files
app.get('/api/v1/files', (_req: Request, res: Response) => {
  const allFiles: Array<FileTelemetry & { hostname: string; agentId: string }> = [];
  for (const agent of agents.values()) {
    if (agent.fileEvents) {
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

// GET /api/v1/quarantine
app.get('/api/v1/quarantine', (_req: Request, res: Response) => {
  res.json(quarantineHistory);
});

// GET /api/v1/rules
app.get('/api/v1/rules', (_req: Request, res: Response) => {
  res.json(activeRules);
});

// GET /api/v1/alerts
app.get('/api/v1/alerts', (_req: Request, res: Response) => {
  res.json(alertsHistory);
});

// GET /api/v1/events
app.get('/api/v1/events', (_req: Request, res: Response) => {
  res.json(eventsHistory.slice(0, 100));
});

// POST /api/v1/agents/register (Protected by verifyAgentToken & DEDUPLICATED BY HOSTNAME)
app.post('/api/v1/agents/register', verifyAgentToken, (req: Request, res: Response) => {
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
  saveStorage();
  saveAgentToDb(updatedAgent);
  broadcastSSE('agent_registered', updatedAgent);

  res.status(201).json({ agentId, status: 'registered', expectedPayloadCase: 'camelCase_or_snake_case' });
});

// POST /api/v1/agents/heartbeat (Protected by verifyAgentToken)
app.post('/api/v1/agents/heartbeat', verifyAgentToken, (req: Request, res: Response) => {
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
  if (payload.topProcesses) {
    agent.topProcesses = payload.topProcesses;
  }
  if (payload.networkConnections) {
    agent.networkConnections = payload.networkConnections;
  }
  if (payload.fileEvents) {
    agent.fileEvents = payload.fileEvents;
  }

  saveAgentToDb(agent);

  res.json({ status: 'acknowledged', nextHeartbeatIntervalSec: 30 });
});

// Start DB Initialization & Server Listen & Deep Discovery
initDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`🛡️ Guardian Core API Server running on port ${PORT} [Deep Discovery Engine Active]`);
    
    // Deep Discovery on Startup
    const detectedSubnets = getLocalSubnets();
    performDeepNetworkDiscovery(detectedSubnets[0] || '192.168.50');
  });
});
