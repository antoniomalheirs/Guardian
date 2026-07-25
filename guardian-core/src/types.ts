export interface SystemInventory {
  hostname: string;
  osName: string;
  osVersion: string;
  architecture: string;
  cpuModel: string;
  totalMemoryMb: number;
  ipAddress: string;
  macAddress: string;
}

export interface ProcessTelemetry {
  pid: number;
  parentPid?: number | null;
  name: string;
  executablePath: string;
  commandLine?: string;
  cpuPct: number;
  memoryMb: number;
  sha256Hash: string;
}

export interface NetworkTelemetry {
  pid: number;
  processName: string;
  protocol: string;
  localAddress: string;
  localPort: number;
  remoteAddress: string;
  remotePort: number;
  status: string;
}

export interface FileTelemetry {
  filePath: string;
  action: 'CREATED' | 'MODIFIED' | 'DELETED' | 'RENAMED';
  fileSizeBytes: number;
  timestamp: string;
  yaraMatches?: string[];
}

export interface QuarantineRecord {
  quarantineId: string;
  agentId: string;
  hostname: string;
  filePath: string;
  sha256Hash: string;
  reason: string;
  quarantinedAt: string;
  status: 'QUARANTINED' | 'RESTORED' | 'DELETED';
}

export interface DiscoveredDevice {
  ipAddress: string;
  macAddress: string;
  vendorName: string;
  deviceType: 'WINDOWS' | 'LINUX' | 'ROUTER' | 'PRINTER' | 'IOT' | 'UNKNOWN';
  openPorts: number[];
  riskScore: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  detectedThreats: string[];
  lastSeen: string;
}

export interface NetworkScanResult {
  scanId: string;
  subnet: string;
  scannedAt: string;
  totalDiscovered: number;
  devices: DiscoveredDevice[];
}

export interface SecurityFinding {
  findingType: string;
  severity: 'INFO' | 'WARNING' | 'HIGH' | 'CRITICAL';
  description: string;
  evidence: string;
  mitreId: string;
}

export interface AgentCommand {
  commandId: string;
  type: 'KILL_PROCESS' | 'ISOLATE_NETWORK';
  payload: Record<string, any>;
  createdAt: string;
}

export interface TelemetryPayload {
  agentId: string;
  timestamp: string;
  cpuUsagePct: number;
  memoryUsagePct: number;
  diskUsagePct: number;
  activeProcessesCount: number;
  eventsCount: number;
  topProcesses?: ProcessTelemetry[];
  networkConnections?: NetworkTelemetry[];
  fileEvents?: FileTelemetry[];
  securityFindings?: SecurityFinding[];
}

export interface AgentRecord {
  agentId: string;
  hostname: string;
  status: 'online' | 'offline' | 'warning' | 'isolated';
  inventory: SystemInventory;
  lastHeartbeat: string;
  metrics: {
    cpuUsagePct: number;
    memoryUsagePct: number;
    diskUsagePct: number;
    activeProcessesCount: number;
  };
  topProcesses: ProcessTelemetry[];
  networkConnections: NetworkTelemetry[];
  fileEvents: FileTelemetry[];
  quarantinedFiles?: QuarantineRecord[];
}

export interface RuleDefinition {
  ruleId: string;
  name: string;
  category: 'PROCESS' | 'FILE' | 'NETWORK' | 'BEHAVIOR';
  severity: 'INFO' | 'WARNING' | 'HIGH' | 'CRITICAL';
  description: string;
  enabled: boolean;
}

export interface EDRAlert {
  alertId: string;
  agentId: string;
  hostname: string;
  ruleId: string;
  ruleName: string;
  severity: 'INFO' | 'WARNING' | 'HIGH' | 'CRITICAL';
  timestamp: string;
  details: string;
  status: 'ACTIVE' | 'MITIGATED' | 'DISMISSED';
}

export interface EDREvent {
  id: string;
  agentId: string;
  hostname: string;
  timestamp: string;
  category: 'PROCESS' | 'FILE' | 'NETWORK' | 'SERVICE' | 'REGISTRY' | 'SECURITY';
  severity: 'INFO' | 'WARNING' | 'HIGH' | 'CRITICAL';
  description: string;
  details: Record<string, any>;
}

export interface YaraRule {
  ruleId: string;
  name: string;
  threatType: 'MIMIKATZ' | 'COBALT_STRIKE' | 'WEBSHELL' | 'RANSOMWARE' | 'EXPLOIT';
  severity: 'WARNING' | 'HIGH' | 'CRITICAL';
  strings: string[];
  description: string;
  mitreId: string;
}
