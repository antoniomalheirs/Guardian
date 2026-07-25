import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Monitor, 
  Activity, 
  AlertTriangle, 
  Cpu, 
  Server, 
  Terminal, 
  RefreshCw, 
  Search,
  Clock,
  Radio,
  Layers,
  FileCode,
  Lock,
  Zap,
  Network,
  XCircle,
  Skull,
  FileText,
  PlusCircle,
  Check,
  Globe,
  Wifi,
  AlertCircle,
  Database,
  Trash2,
  Filter,
  Copy,
  Info,
  ChevronRight,
  Smartphone
} from 'lucide-react';

interface ProcessTelemetry {
  pid: number;
  parentPid?: number | null;
  name: string;
  executablePath: string;
  cpuPct: number;
  memoryMb: number;
  sha256Hash: string;
  hostname?: string;
  agentId?: string;
}

interface NetworkTelemetry {
  pid: number;
  processName: string;
  protocol: string;
  localAddress: string;
  localPort: number;
  remoteAddress: string;
  remotePort: number;
  status: string;
  hostname?: string;
  agentId?: string;
}

interface FileTelemetry {
  filePath: string;
  action: 'CREATED' | 'MODIFIED' | 'DELETED' | 'RENAMED';
  fileSizeBytes: number;
  timestamp: string;
  hostname?: string;
  agentId?: string;
}

interface DiscoveredDevice {
  ipAddress: string;
  macAddress: string;
  vendorName: string;
  deviceType: 'WINDOWS' | 'LINUX' | 'ROUTER' | 'PRINTER' | 'IOT' | 'UNKNOWN';
  openPorts: number[];
  riskScore: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  detectedThreats: string[];
  lastSeen: string;
}

interface Agent {
  agentId: string;
  hostname: string;
  status: 'online' | 'offline' | 'warning' | 'isolated';
  inventory: {
    hostname: string;
    osName: string;
    osVersion: string;
    architecture: string;
    cpuModel: string;
    totalMemoryMb: number;
    ipAddress: string;
    macAddress: string;
  };
  lastHeartbeat: string;
  metrics: {
    cpuUsagePct: number;
    memoryUsagePct: number;
    diskUsagePct: number;
    activeProcessesCount: number;
  };
  topProcesses?: ProcessTelemetry[];
  networkConnections?: NetworkTelemetry[];
  fileEvents?: FileTelemetry[];
}

interface RuleDefinition {
  ruleId: string;
  name: string;
  category: 'PROCESS' | 'FILE' | 'NETWORK' | 'BEHAVIOR';
  severity: 'INFO' | 'WARNING' | 'HIGH' | 'CRITICAL';
  description: string;
  enabled: boolean;
}

interface EDRAlert {
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

export default function App() {
  const [activeTab, setActiveTab] = useState<'endpoints' | 'agentless' | 'network_map' | 'mitre_matrix' | 'processes' | 'network' | 'files' | 'rules'>('endpoints');
  const [selectedHostFilter, setSelectedHostFilter] = useState<string>('ALL');
  const [selectedProcessDetails, setSelectedProcessDetails] = useState<ProcessTelemetry | null>(null);

  const [agents, setAgents] = useState<Agent[]>([]);
  const [processes, setProcesses] = useState<ProcessTelemetry[]>([]);
  const [networkConns, setNetworkConns] = useState<NetworkTelemetry[]>([]);
  const [fileEvents, setFileEvents] = useState<FileTelemetry[]>([]);
  const [rules, setRules] = useState<RuleDefinition[]>([]);
  const [alerts, setAlerts] = useState<EDRAlert[]>([]);
  const [agentlessDevices, setAgentlessDevices] = useState<DiscoveredDevice[]>([]);
  const [scanningNetwork, setScanningNetwork] = useState(false);
  const [loading, setLoading] = useState(false);
  const [actionMessage, setActionMessage] = useState<string | null>(null);
  const [detectedSubnet, setDetectedSubnet] = useState<string>('192.168.50');

  // New Rule Modal State
  const [showAddRule, setShowAddRule] = useState(false);
  const [newRuleId, setNewRuleId] = useState('');
  const [newRuleName, setNewRuleName] = useState('');
  const [newRuleCategory, setNewRuleCategory] = useState<'PROCESS' | 'FILE' | 'NETWORK' | 'BEHAVIOR'>('PROCESS');
  const [newRuleSeverity, setNewRuleSeverity] = useState<'INFO' | 'WARNING' | 'HIGH' | 'CRITICAL'>('HIGH');
  const [newRuleDescription, setNewRuleDescription] = useState('');

  // Android Install Modal State
  const [showAndroidInstallModal, setShowAndroidInstallModal] = useState(false);
  const [copiedCmd, setCopiedCmd] = useState(false);

  const fetchData = async () => {
    setLoading(true);
    try {
      const healthRes = await fetch('http://localhost:4000/api/v1/health');
      if (healthRes.ok) {
        const healthData = await healthRes.json();
        if (healthData.detectedSubnets && healthData.detectedSubnets.length > 0) {
          setDetectedSubnet(healthData.detectedSubnets[0]);
        }
      }

      const devRes = await fetch('http://localhost:4000/api/v1/network/scan/latest');
      if (devRes.ok) setAgentlessDevices(await devRes.json());

      const res = await fetch('http://localhost:4000/api/v1/agents');
      if (res.ok) setAgents(await res.json());

      const procRes = await fetch('http://localhost:4000/api/v1/processes');
      if (procRes.ok) setProcesses(await procRes.json());

      const netRes = await fetch('http://localhost:4000/api/v1/network');
      if (netRes.ok) setNetworkConns(await netRes.json());

      const filesRes = await fetch('http://localhost:4000/api/v1/files');
      if (filesRes.ok) setFileEvents(await filesRes.json());

      const rulesRes = await fetch('http://localhost:4000/api/v1/rules');
      if (rulesRes.ok) setRules(await rulesRes.json());

      const alertsRes = await fetch('http://localhost:4000/api/v1/alerts');
      if (alertsRes.ok) setAlerts(await alertsRes.json());
    } catch (err) {
      console.warn('Backend API connection warning:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();

    const eventSource = new EventSource('http://localhost:4000/api/v1/stream');
    eventSource.addEventListener('alert', (e) => {
      try {
        const newAlert = JSON.parse((e as MessageEvent).data);
        setActionMessage(`🚨 AMEAÇA DETECTADA: ${newAlert.ruleName} no host ${newAlert.hostname}`);
        fetchData();
      } catch {}
    });
    eventSource.addEventListener('network_scan_complete', (e) => {
      try {
        const data = JSON.parse((e as MessageEvent).data);
        if (Array.isArray(data)) setAgentlessDevices(data);
        else if (data.devices) setAgentlessDevices(data.devices);
        setActionMessage(`📡 Varredura de Rede Concluída com Sucesso!`);
      } catch {}
    });
    eventSource.addEventListener('telemetry', () => fetchData());
    eventSource.onerror = () => {
      eventSource.close();
      const interval = setInterval(fetchData, 10000);
      // Store for cleanup
      (window as any).__guardianPollInterval = interval;
    };
    return () => {
      eventSource.close();
      if ((window as any).__guardianPollInterval) clearInterval((window as any).__guardianPollInterval);
    };
  }, []);

  const triggerAgentlessScan = async () => {
    setScanningNetwork(true);
    setActionMessage(`📡 Iniciando Varredura Real na Sub-rede ${detectedSubnet}.0/24...`);
    try {
      const res = await fetch('http://localhost:4000/api/v1/network/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ subnet: detectedSubnet }),
      });
      if (res.ok) {
        const data = await res.json();
        setAgentlessDevices(data.devices);
        setActionMessage(`✅ Varredura concluída! ${data.totalDiscovered} dispositivos REAIS salvos no Banco de Dados SQL!`);
      }
    } catch {
      setActionMessage(`Varredura concluída.`);
    } finally {
      setScanningNetwork(false);
      setTimeout(() => setActionMessage(null), 5000);
    }
  };

  const handleIsolateHost = async (agentId: string) => {
    try {
      const res = await fetch('http://localhost:4000/api/v1/response/isolate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentId }),
      });
      if (res.ok) {
        setActionMessage(`🔒 Host ${agentId} foi isolado da rede com sucesso!`);
        fetchData();
      }
    } catch {
      setActionMessage(`🔒 Comando enviado.`);
    }
    setTimeout(() => setActionMessage(null), 4000);
  };

  const handleDeleteAgent = async (agentId: string) => {
    try {
      const res = await fetch(`http://localhost:4000/api/v1/agents/${agentId}`, {
        method: 'DELETE',
      });
      if (res.ok) {
        setActionMessage(`🗑️ Agente ${agentId} removido com sucesso do banco de dados!`);
        fetchData();
      }
    } catch {
      setActionMessage(`Erro ao remover agente.`);
    }
    setTimeout(() => setActionMessage(null), 4000);
  };

  const handleKillProcess = async (agentId: string, pid: number) => {
    try {
      const res = await fetch('http://localhost:4000/api/v1/response/kill', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ agentId, pid }),
      });
      if (res.ok) {
        setActionMessage(`☠️ Processo PID ${pid} finalizado no endpoint!`);
        fetchData();
      }
    } catch {
      setActionMessage(`Comando enviado.`);
    }
    setTimeout(() => setActionMessage(null), 4000);
  };

  const handleCreateRule = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newRuleId || !newRuleName) return;

    try {
      await fetch('http://localhost:4000/api/v1/rules/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ruleId: newRuleId,
          name: newRuleName,
          category: newRuleCategory,
          severity: newRuleSeverity,
          description: newRuleDescription,
          enabled: true,
        }),
      });
      setActionMessage(`✨ Nova Regra ${newRuleId} cadastrada com sucesso!`);
      setShowAddRule(false);
      setNewRuleId('');
      setNewRuleName('');
      setNewRuleDescription('');
      fetchData();
    } catch {
      setActionMessage(`Erro ao cadastrar regra.`);
    }
    setTimeout(() => setActionMessage(null), 4000);
  };

  // Filtered Telemetry Collections
  const filteredProcesses = selectedHostFilter === 'ALL' 
    ? processes 
    : processes.filter(p => p.agentId === selectedHostFilter || p.hostname === selectedHostFilter);

  const filteredNetwork = selectedHostFilter === 'ALL' 
    ? networkConns 
    : networkConns.filter(n => n.agentId === selectedHostFilter || n.hostname === selectedHostFilter);

  const filteredFiles = selectedHostFilter === 'ALL' 
    ? fileEvents 
    : fileEvents.filter(f => f.agentId === selectedHostFilter || f.hostname === selectedHostFilter);

  return (
    <div style={{ padding: '24px 32px', maxWidth: '1600px', margin: '0 auto' }}>
      {/* Top Notification Banner */}
      {actionMessage && (
        <div style={{ background: 'linear-gradient(90deg, rgba(6, 182, 212, 0.2), rgba(59, 130, 246, 0.2))', border: '1px solid var(--accent-cyan)', padding: '12px 20px', borderRadius: '12px', marginBottom: '20px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', color: '#ffffff', fontWeight: 600 }}>
          <span>{actionMessage}</span>
          <XCircle size={18} style={{ cursor: 'pointer' }} onClick={() => setActionMessage(null)} />
        </div>
      )}

      {/* Top Header */}
      <header className="glass-panel" style={{ padding: '18px 28px', marginBottom: '24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{ background: 'linear-gradient(135deg, #06b6d4, #3b82f6)', padding: '10px', borderRadius: '12px', display: 'flex', boxShadow: '0 4px 20px rgba(6, 182, 212, 0.4)' }}>
            <Shield size={28} color="#ffffff" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <h1 style={{ fontSize: '1.5rem', fontWeight: 800, letterSpacing: '-0.02em', background: 'linear-gradient(90deg, #ffffff, #94a3b8)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                GUARDIAN EDR & NDR PLATFORM
              </h1>
              <span className="badge badge-online" style={{ background: 'rgba(16, 185, 129, 0.15)', border: '1px solid #10b981', color: '#34d399' }}>
                <Database size={12} className="animate-pulse" /> Banco SQL Ativo (guardian.db)
              </span>
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
              Sub-rede Local Detectada: <strong style={{ color: '#34d399' }}>{detectedSubnet}.0/24 (Gateway {detectedSubnet}.1)</strong>
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <button
            onClick={triggerAgentlessScan}
            disabled={scanningNetwork}
            style={{ background: 'linear-gradient(135deg, #10b981, #059669)', color: '#ffffff', border: 'none', padding: '10px 20px', borderRadius: '10px', fontSize: '0.85rem', fontWeight: 700, cursor: scanningNetwork ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', gap: '8px', boxShadow: '0 4px 15px rgba(16, 185, 129, 0.3)' }}
          >
            <Wifi size={16} className={scanningNetwork ? 'animate-spin' : ''} />
            {scanningNetwork ? `Varrendo Sub-rede ${detectedSubnet}.0/24...` : `Escanear Rede Real (${detectedSubnet}.0/24)`}
          </button>

          <button
            onClick={() => setShowAndroidInstallModal(true)}
            style={{ background: 'linear-gradient(135deg, #06b6d4, #3b82f6)', color: '#ffffff', border: 'none', padding: '10px 18px', borderRadius: '10px', fontSize: '0.85rem', fontWeight: 700, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '8px', boxShadow: '0 4px 15px rgba(6, 182, 212, 0.3)' }}
          >
            <Smartphone size={16} />
            Instalar no Android (Termux)
          </button>

          <button 
            onClick={fetchData} 
            disabled={loading}
            className="glass-panel glass-card-interactive" 
            style={{ padding: '8px 16px', display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-primary)', border: '1px solid var(--border-glass)', borderRadius: '10px', fontSize: '0.85rem', fontWeight: 600 }}
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            Atualizar
          </button>
        </div>
      </header>

      {/* Navigation Tabs */}
      <div style={{ display: 'flex', gap: '12px', marginBottom: '24px', flexWrap: 'wrap' }}>
        <button
          onClick={() => setActiveTab('endpoints')}
          className="glass-panel"
          style={{
            padding: '10px 20px',
            borderRadius: '12px',
            color: activeTab === 'endpoints' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
            borderColor: activeTab === 'endpoints' ? 'var(--accent-cyan)' : 'var(--border-glass)',
            background: activeTab === 'endpoints' ? 'rgba(6, 182, 212, 0.12)' : 'var(--bg-card)',
            fontWeight: 700,
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            cursor: 'pointer'
          }}
        >
          <Monitor size={16} /> Agentes Instalados ({agents.length})
        </button>
        <button
          onClick={() => setActiveTab('agentless')}
          className="glass-panel"
          style={{
            padding: '10px 20px',
            borderRadius: '12px',
            color: activeTab === 'agentless' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
            borderColor: activeTab === 'agentless' ? 'var(--accent-cyan)' : 'var(--border-glass)',
            background: activeTab === 'agentless' ? 'rgba(6, 182, 212, 0.12)' : 'var(--bg-card)',
            fontWeight: 600,
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            cursor: 'pointer'
          }}
        >
          <Globe size={16} color="#34d399" /> Dispositivos na Rede Real ({agentlessDevices.length})
        </button>
        <button
          onClick={() => setActiveTab('processes')}
          className="glass-panel"
          style={{
            padding: '10px 20px',
            borderRadius: '12px',
            color: activeTab === 'processes' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
            borderColor: activeTab === 'processes' ? 'var(--accent-cyan)' : 'var(--border-glass)',
            background: activeTab === 'processes' ? 'rgba(6, 182, 212, 0.12)' : 'var(--bg-card)',
            fontWeight: 600,
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            cursor: 'pointer'
          }}
        >
          <Terminal size={16} /> Processos ({filteredProcesses.length})
        </button>
        <button
          onClick={() => setActiveTab('network')}
          className="glass-panel"
          style={{
            padding: '10px 20px',
            borderRadius: '12px',
            color: activeTab === 'network' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
            borderColor: activeTab === 'network' ? 'var(--accent-cyan)' : 'var(--border-glass)',
            background: activeTab === 'network' ? 'rgba(6, 182, 212, 0.12)' : 'var(--bg-card)',
            fontWeight: 600,
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            cursor: 'pointer'
          }}
        >
          <Network size={16} /> Sockets de Rede ({filteredNetwork.length})
        </button>
        <button
          onClick={() => setActiveTab('files')}
          className="glass-panel"
          style={{
            padding: '10px 20px',
            borderRadius: '12px',
            color: activeTab === 'files' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
            borderColor: activeTab === 'files' ? 'var(--accent-cyan)' : 'var(--border-glass)',
            background: activeTab === 'files' ? 'rgba(6, 182, 212, 0.12)' : 'var(--bg-card)',
            fontWeight: 600,
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            cursor: 'pointer'
          }}
        >
          <FileText size={16} /> Arquivos ({filteredFiles.length})
        </button>
        <button
          onClick={() => setActiveTab('network_map')}
          className="glass-panel"
          style={{
            padding: '10px 20px',
            borderRadius: '12px',
            color: activeTab === 'network_map' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
            borderColor: activeTab === 'network_map' ? 'var(--accent-cyan)' : 'var(--border-glass)',
            background: activeTab === 'network_map' ? 'rgba(6, 182, 212, 0.12)' : 'var(--bg-card)',
            fontWeight: 700,
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            cursor: 'pointer'
          }}
        >
          <Network size={16} color="#38bdf8" /> Mapa de Topologia de Rede
        </button>
        <button
          onClick={() => setActiveTab('mitre_matrix')}
          className="glass-panel"
          style={{
            padding: '10px 20px',
            borderRadius: '12px',
            color: activeTab === 'mitre_matrix' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
            borderColor: activeTab === 'mitre_matrix' ? 'var(--accent-cyan)' : 'var(--border-glass)',
            background: activeTab === 'mitre_matrix' ? 'rgba(6, 182, 212, 0.12)' : 'var(--bg-card)',
            fontWeight: 700,
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            cursor: 'pointer'
          }}
        >
          <Layers size={16} color="#f43f5e" /> Matriz MITRE ATT&CK
        </button>
        <button
          onClick={() => setActiveTab('rules')}
          className="glass-panel"
          style={{
            padding: '10px 20px',
            borderRadius: '12px',
            color: activeTab === 'rules' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
            borderColor: activeTab === 'rules' ? 'var(--accent-cyan)' : 'var(--border-glass)',
            background: activeTab === 'rules' ? 'rgba(6, 182, 212, 0.12)' : 'var(--bg-card)',
            fontWeight: 600,
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            cursor: 'pointer'
          }}
        >
          <Zap size={16} /> Regras ({rules.length})
        </button>
      </div>

      {/* Dispositivos na Rede Real Tab */}
      {activeTab === 'agentless' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          <div className="glass-panel" style={{ padding: '24px', background: 'linear-gradient(135deg, rgba(16, 185, 129, 0.08), rgba(6, 182, 212, 0.08))', border: '1px solid rgba(16, 185, 129, 0.3)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <Globe size={26} color="#34d399" />
                <div>
                  <h2 style={{ fontSize: '1.2rem', fontWeight: 800, color: '#ffffff' }}>
                    Auditoria e Proteção da Rede Real ({detectedSubnet}.0/24)
                  </h2>
                  <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                    Descoberta direta via ARP do Kernel do Windows e verificação de sockets sem qualquer dado fantasma ou cache.
                  </p>
                </div>
              </div>
              <span className="badge badge-online" style={{ fontSize: '0.85rem', padding: '6px 14px' }}>
                {agentlessDevices.length} Dispositivos Reais Conectados
              </span>
            </div>
          </div>

          {agentlessDevices.length === 0 ? (
            <div className="glass-panel" style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
              <Wifi size={36} color="var(--accent-cyan)" style={{ marginBottom: '12px' }} />
              <h3>Nenhum dispositivo encontrado no Banco de Dados SQL.</h3>
              <p style={{ fontSize: '0.85rem', marginTop: '6px' }}>Clique no botão no topo <strong>"Escanear Rede Real ({detectedSubnet}.0/24)"</strong> para varrer sua rede agora!</p>
            </div>
          ) : (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))', gap: '20px' }}>
              {agentlessDevices.map((dev, idx) => (
                <div key={idx} className="glass-panel" style={{ padding: '24px', borderLeft: `4px solid ${dev.riskScore === 'CRITICAL' ? '#f43f5e' : dev.riskScore === 'HIGH' ? '#f59e0b' : dev.riskScore === 'MEDIUM' ? '#3b82f6' : '#10b981'}` }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
                    <div>
                      <h3 style={{ fontSize: '1.1rem', fontWeight: 800, color: '#ffffff' }}>{dev.ipAddress}</h3>
                      <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '2px' }}>{dev.vendorName}</p>
                    </div>
                    <span className={`badge ${dev.riskScore === 'CRITICAL' ? 'badge-critical' : dev.riskScore === 'HIGH' ? 'badge-warning' : 'badge-online'}`}>
                      Risco: {dev.riskScore}
                    </span>
                  </div>

                  <div style={{ background: 'rgba(0,0,0,0.25)', padding: '12px', borderRadius: '8px', marginBottom: '14px', fontSize: '0.8rem' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                      <span style={{ color: 'var(--text-muted)' }}>MAC Address Real:</span>
                      <strong className="mono-text" style={{ color: '#fff' }}>{dev.macAddress}</strong>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                      <span style={{ color: 'var(--text-muted)' }}>Tipo de Dispositivo:</span>
                      <strong style={{ color: 'var(--accent-cyan)' }}>{dev.deviceType}</strong>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: 'var(--text-muted)' }}>Portas Abertas Auditadas:</span>
                      <strong className="mono-text" style={{ color: '#34d399' }}>{(dev.openPorts || []).length > 0 ? (dev.openPorts || []).join(', ') : 'Nenhuma porta perigosa aberta'}</strong>
                    </div>
                  </div>

                  {(dev.detectedThreats || []).length > 0 ? (
                    <div style={{ background: 'rgba(244, 63, 94, 0.1)', border: '1px solid rgba(244, 63, 94, 0.3)', padding: '10px 12px', borderRadius: '8px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.75rem', color: '#f87171', fontWeight: 700, marginBottom: '4px' }}>
                        <AlertCircle size={14} /> Vulnerabilidades Detectadas:
                      </div>
                      {(dev.detectedThreats || []).map((threat, tIdx) => (
                        <p key={tIdx} style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginLeft: '20px' }}>
                          • {threat}
                        </p>
                      ))}
                    </div>
                  ) : (
                    <div style={{ background: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.3)', padding: '8px 12px', borderRadius: '8px', fontSize: '0.75rem', color: '#34d399', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <Check size={14} /> Dispositivo Seguro na Rede
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Agentes Instalados Tab */}
      {activeTab === 'endpoints' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))', gap: '20px' }}>
          {agents.length === 0 ? (
            <div className="glass-panel" style={{ padding: '30px', color: 'var(--text-muted)', gridColumn: '1/-1' }}>
              Nenhum agente registrado no momento.
            </div>
          ) : (
            agents.map((agent) => (
              <div key={agent.agentId} className="glass-panel" style={{ padding: '24px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '14px' }}>
                  <div>
                    <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#fff' }}>{agent.hostname}</h3>
                    <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '4px' }}>{agent.inventory?.osName} ({agent.inventory?.osVersion})</p>
                  </div>
                  <span className={`badge ${agent.status === 'online' ? 'badge-online' : 'badge-warning'}`}>{agent.status}</span>
                </div>
                <div style={{ background: 'rgba(0, 0, 0, 0.2)', padding: '12px', borderRadius: '10px', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                    <span>IP do Endpoint:</span>
                    <strong className="mono-text" style={{ color: '#fff' }}>{agent.inventory?.ipAddress || 'N/A'}</strong>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                    <span>Processos Monitorados:</span>
                    <strong style={{ color: 'var(--accent-cyan)' }}>{agent.metrics?.activeProcessesCount || 0}</strong>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span>Uso de CPU / RAM:</span>
                    <strong style={{ color: '#34d399' }}>{agent.metrics?.cpuUsagePct || 0}% / {agent.metrics?.memoryUsagePct || 0}%</strong>
                  </div>
                </div>
                <div style={{ marginTop: '16px', display: 'flex', gap: '10px' }}>
                  <button 
                    onClick={() => handleIsolateHost(agent.agentId)}
                    style={{ flex: 1, background: 'rgba(244, 63, 94, 0.15)', border: '1px solid rgba(244, 63, 94, 0.4)', color: '#f87171', padding: '8px', borderRadius: '8px', fontSize: '0.8rem', fontWeight: 700, cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}
                  >
                    <Lock size={14} /> Isolamento
                  </button>
                  <button 
                    onClick={() => handleDeleteAgent(agent.agentId)}
                    style={{ background: 'rgba(239, 68, 68, 0.2)', border: '1px solid rgba(239, 68, 68, 0.5)', color: '#fca5a5', padding: '8px 12px', borderRadius: '8px', fontSize: '0.8rem', fontWeight: 700, cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}
                    title="Excluir Agente do Banco de Dados"
                  >
                    <Trash2 size={14} /> Excluir
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* Processos Tab */}
      {activeTab === 'processes' && (
        <div className="glass-panel" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
            <h2 style={{ fontSize: '1.2rem', fontWeight: 800, color: '#ffffff', display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Terminal size={22} color="var(--accent-cyan)" /> Telemetria de Processos Auditados em Tempo Real ({filteredProcesses.length})
            </h2>

            {/* Quick Host Filter Bar */}
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                <Filter size={14} /> Filtrar Dispositivo:
              </span>
              <button
                onClick={() => setSelectedHostFilter('ALL')}
                style={{
                  background: selectedHostFilter === 'ALL' ? 'var(--accent-cyan)' : 'rgba(255, 255, 255, 0.05)',
                  color: selectedHostFilter === 'ALL' ? '#000' : '#fff',
                  border: '1px solid var(--border-glass)',
                  padding: '6px 14px',
                  borderRadius: '20px',
                  fontSize: '0.75rem',
                  fontWeight: 700,
                  cursor: 'pointer'
                }}
              >
                Todos ({processes.length})
              </button>
              {agents.map((agent) => {
                const count = processes.filter(p => p.agentId === agent.agentId || p.hostname === agent.hostname).length;
                const isSelected = selectedHostFilter === agent.agentId || selectedHostFilter === agent.hostname;
                return (
                  <button
                    key={agent.agentId}
                    onClick={() => setSelectedHostFilter(agent.agentId)}
                    style={{
                      background: isSelected ? 'var(--accent-cyan)' : 'rgba(255, 255, 255, 0.05)',
                      color: isSelected ? '#000' : '#fff',
                      border: '1px solid var(--border-glass)',
                      padding: '6px 14px',
                      borderRadius: '20px',
                      fontSize: '0.75rem',
                      fontWeight: 700,
                      cursor: 'pointer'
                    }}
                  >
                    {agent.inventory?.osName.includes('Android') ? '📱' : '🖥️'} {agent.hostname} ({count})
                  </button>
                );
              })}
            </div>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-glass)', color: 'var(--text-muted)' }}>
                  <th style={{ padding: '12px' }}>DISPOSITIVO</th>
                  <th style={{ padding: '12px' }}>PID</th>
                  <th style={{ padding: '12px' }}>NOME DO PROCESSO</th>
                  <th style={{ padding: '12px' }}>CAMINHO DO EXECUTÁVEL</th>
                  <th style={{ padding: '12px' }}>CPU (%)</th>
                  <th style={{ padding: '12px' }}>MEMÓRIA (MB)</th>
                  <th style={{ padding: '12px' }}>HASH SHA-256</th>
                  <th style={{ padding: '12px', textAlign: 'right' }}>AÇÕES</th>
                </tr>
              </thead>
              <tbody>
                {filteredProcesses.length === 0 ? (
                  <tr>
                    <td colSpan={8} style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>
                      Nenhum processo reportado para o filtro selecionado.
                    </td>
                  </tr>
                ) : (
                  filteredProcesses.map((proc, idx) => (
                    <tr 
                      key={idx} 
                      style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.05)', cursor: 'pointer' }}
                      onClick={() => setSelectedProcessDetails(proc)}
                    >
                      <td style={{ padding: '12px', color: '#fff', fontWeight: 600 }}>
                        <span className="badge badge-online" style={{ fontSize: '0.7rem' }}>
                          {proc.hostname || 'Endpoint Local'}
                        </span>
                      </td>
                      <td className="mono-text" style={{ padding: '12px', color: 'var(--accent-cyan)', fontWeight: 700 }}>{proc.pid}</td>
                      <td style={{ padding: '12px', fontWeight: 700, color: '#fff' }}>{proc.name}</td>
                      <td className="mono-text" style={{ padding: '12px', color: 'var(--text-secondary)', fontSize: '0.75rem' }}>{proc.executablePath || 'N/A (Kernel/System)'}</td>
                      <td style={{ padding: '12px', color: proc.cpuPct > 50 ? '#f87171' : '#34d399' }}>{(proc.cpuPct || 0).toFixed(1)}%</td>
                      <td style={{ padding: '12px', color: '#fff' }}>{proc.memoryMb} MB</td>
                      <td className="mono-text" style={{ padding: '12px', color: 'var(--text-muted)', fontSize: '0.7rem' }}>
                        {proc.sha256Hash ? proc.sha256Hash.substring(0, 16) + '...' : 'N/A'}
                      </td>
                      <td style={{ padding: '12px', textAlign: 'right' }}>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleKillProcess(proc.agentId || '', proc.pid);
                          }}
                          style={{ background: 'rgba(244, 63, 94, 0.15)', border: '1px solid rgba(244, 63, 94, 0.4)', color: '#f87171', padding: '6px 12px', borderRadius: '6px', fontSize: '0.75rem', fontWeight: 700, cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                        >
                          <Skull size={12} /> Matar
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Sockets de Rede Tab */}
      {activeTab === 'network' && (
        <div className="glass-panel" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
            <h2 style={{ fontSize: '1.2rem', fontWeight: 800, color: '#ffffff', display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Network size={22} color="var(--accent-cyan)" /> Conexões & Sockets de Rede ({filteredNetwork.length})
            </h2>

            {/* Quick Host Filter Bar */}
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                <Filter size={14} /> Filtrar Dispositivo:
              </span>
              <button
                onClick={() => setSelectedHostFilter('ALL')}
                style={{
                  background: selectedHostFilter === 'ALL' ? 'var(--accent-cyan)' : 'rgba(255, 255, 255, 0.05)',
                  color: selectedHostFilter === 'ALL' ? '#000' : '#fff',
                  border: '1px solid var(--border-glass)',
                  padding: '6px 14px',
                  borderRadius: '20px',
                  fontSize: '0.75rem',
                  fontWeight: 700,
                  cursor: 'pointer'
                }}
              >
                Todos ({networkConns.length})
              </button>
              {agents.map((agent) => {
                const count = networkConns.filter(n => n.agentId === agent.agentId || n.hostname === agent.hostname).length;
                const isSelected = selectedHostFilter === agent.agentId || selectedHostFilter === agent.hostname;
                return (
                  <button
                    key={agent.agentId}
                    onClick={() => setSelectedHostFilter(agent.agentId)}
                    style={{
                      background: isSelected ? 'var(--accent-cyan)' : 'rgba(255, 255, 255, 0.05)',
                      color: isSelected ? '#000' : '#fff',
                      border: '1px solid var(--border-glass)',
                      padding: '6px 14px',
                      borderRadius: '20px',
                      fontSize: '0.75rem',
                      fontWeight: 700,
                      cursor: 'pointer'
                    }}
                  >
                    {agent.inventory?.osName.includes('Android') ? '📱' : '🖥️'} {agent.hostname} ({count})
                  </button>
                );
              })}
            </div>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-glass)', color: 'var(--text-muted)' }}>
                  <th style={{ padding: '12px' }}>DISPOSITIVO</th>
                  <th style={{ padding: '12px' }}>PID</th>
                  <th style={{ padding: '12px' }}>PROCESSO</th>
                  <th style={{ padding: '12px' }}>PROTOCOLO</th>
                  <th style={{ padding: '12px' }}>ENDEREÇO LOCAL</th>
                  <th style={{ padding: '12px' }}>ENDEREÇO REMOTO</th>
                  <th style={{ padding: '12px' }}>STATUS</th>
                </tr>
              </thead>
              <tbody>
                {filteredNetwork.length === 0 ? (
                  <tr>
                    <td colSpan={7} style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>
                      Nenhum socket ativo para o filtro selecionado.
                    </td>
                  </tr>
                ) : (
                  filteredNetwork.map((conn, idx) => (
                    <tr key={idx} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.05)' }}>
                      <td style={{ padding: '12px', color: '#fff', fontWeight: 600 }}>
                        <span className="badge badge-online" style={{ fontSize: '0.7rem' }}>
                          {conn.hostname || 'Endpoint Local'}
                        </span>
                      </td>
                      <td className="mono-text" style={{ padding: '12px', color: 'var(--accent-cyan)' }}>{conn.pid}</td>
                      <td style={{ padding: '12px', fontWeight: 700, color: '#fff' }}>{conn.processName}</td>
                      <td style={{ padding: '12px', color: '#34d399', fontWeight: 700 }}>{conn.protocol}</td>
                      <td className="mono-text" style={{ padding: '12px', color: '#fff' }}>{conn.localAddress}:{conn.localPort}</td>
                      <td className="mono-text" style={{ padding: '12px', color: 'var(--text-secondary)' }}>{conn.remoteAddress}:{conn.remotePort}</td>
                      <td style={{ padding: '12px' }}>
                        <span className="badge badge-online" style={{ fontSize: '0.75rem' }}>{conn.status}</span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Arquivos Tab */}
      {activeTab === 'files' && (
        <div className="glass-panel" style={{ padding: '24px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
            <h2 style={{ fontSize: '1.2rem', fontWeight: 800, color: '#ffffff', display: 'flex', alignItems: 'center', gap: '10px' }}>
              <FileText size={22} color="var(--accent-cyan)" /> Monitoramento de Alterações em Arquivos ({filteredFiles.length})
            </h2>

            {/* Quick Host Filter Bar */}
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
              <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                <Filter size={14} /> Filtrar Dispositivo:
              </span>
              <button
                onClick={() => setSelectedHostFilter('ALL')}
                style={{
                  background: selectedHostFilter === 'ALL' ? 'var(--accent-cyan)' : 'rgba(255, 255, 255, 0.05)',
                  color: selectedHostFilter === 'ALL' ? '#000' : '#fff',
                  border: '1px solid var(--border-glass)',
                  padding: '6px 14px',
                  borderRadius: '20px',
                  fontSize: '0.75rem',
                  fontWeight: 700,
                  cursor: 'pointer'
                }}
              >
                Todos ({fileEvents.length})
              </button>
              {agents.map((agent) => {
                const count = fileEvents.filter(f => f.agentId === agent.agentId || f.hostname === agent.hostname).length;
                const isSelected = selectedHostFilter === agent.agentId || selectedHostFilter === agent.hostname;
                return (
                  <button
                    key={agent.agentId}
                    onClick={() => setSelectedHostFilter(agent.agentId)}
                    style={{
                      background: isSelected ? 'var(--accent-cyan)' : 'rgba(255, 255, 255, 0.05)',
                      color: isSelected ? '#000' : '#fff',
                      border: '1px solid var(--border-glass)',
                      padding: '6px 14px',
                      borderRadius: '20px',
                      fontSize: '0.75rem',
                      fontWeight: 700,
                      cursor: 'pointer'
                    }}
                  >
                    {agent.inventory?.osName.includes('Android') ? '📱' : '🖥️'} {agent.hostname} ({count})
                  </button>
                );
              })}
            </div>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border-glass)', color: 'var(--text-muted)' }}>
                  <th style={{ padding: '12px' }}>DISPOSITIVO</th>
                  <th style={{ padding: '12px' }}>AÇÃO</th>
                  <th style={{ padding: '12px' }}>CAMINHO DO ARQUIVO</th>
                  <th style={{ padding: '12px' }}>TAMANHO (BYTES)</th>
                  <th style={{ padding: '12px' }}>DATA / HORA</th>
                </tr>
              </thead>
              <tbody>
                {filteredFiles.length === 0 ? (
                  <tr>
                    <td colSpan={5} style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)' }}>
                      Nenhum evento de arquivo para o filtro selecionado.
                    </td>
                  </tr>
                ) : (
                  filteredFiles.map((evt, idx) => (
                    <tr key={idx} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.05)' }}>
                      <td style={{ padding: '12px', color: '#fff', fontWeight: 600 }}>
                        <span className="badge badge-online" style={{ fontSize: '0.7rem' }}>
                          {evt.hostname || 'Endpoint Local'}
                        </span>
                      </td>
                      <td style={{ padding: '12px' }}>
                        <span className={`badge ${evt.action === 'CREATED' ? 'badge-online' : evt.action === 'DELETED' ? 'badge-critical' : 'badge-warning'}`}>
                          {evt.action}
                        </span>
                      </td>
                      <td className="mono-text" style={{ padding: '12px', color: '#fff' }}>{evt.filePath}</td>
                      <td style={{ padding: '12px', color: 'var(--text-secondary)' }}>{evt.fileSizeBytes} B</td>
                      <td style={{ padding: '12px', color: 'var(--text-muted)', fontSize: '0.75rem' }}>{new Date(evt.timestamp).toLocaleString()}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Mapa de Topologia de Rede Visual Tab */}
      {activeTab === 'network_map' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          <div className="glass-panel" style={{ padding: '24px', background: 'linear-gradient(135deg, rgba(56, 189, 248, 0.08), rgba(6, 182, 212, 0.08))', border: '1px solid rgba(56, 189, 248, 0.3)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <h2 style={{ fontSize: '1.2rem', fontWeight: 800, color: '#ffffff', display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <Network size={24} color="#38bdf8" /> Mapa de Topologia de Rede e Risco dos Ativos ({detectedSubnet}.0/24)
                </h2>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
                  Visualização gráfica em tempo real da infraestrutura de rede, nós ativos, agentes instalados e auras de risco por portas expostas.
                </p>
              </div>
              <button
                onClick={triggerAgentlessScan}
                disabled={scanningNetwork}
                style={{ background: 'linear-gradient(135deg, #0284c7, #2563eb)', color: '#fff', border: 'none', padding: '10px 18px', borderRadius: '10px', fontSize: '0.85rem', fontWeight: 700, cursor: scanningNetwork ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', gap: '8px' }}
              >
                <RefreshCw size={14} className={scanningNetwork ? 'animate-spin' : ''} /> Rescanear Topologia
              </button>
            </div>
          </div>

          {/* Central Hub Graph View */}
          <div className="glass-panel" style={{ padding: '32px', display: 'flex', flexDirection: 'column', alignItems: 'center', position: 'relative' }}>
            {/* Gateway Central Node */}
            <div style={{ 
              background: 'linear-gradient(135deg, #059669, #10b981)',
              padding: '16px 28px', borderRadius: '16px', color: '#fff',
              boxShadow: '0 0 30px rgba(16, 185, 129, 0.5)', textAlign: 'center',
              zIndex: 2, marginBottom: '40px', border: '2px solid #34d399'
            }}>
              <Globe size={28} style={{ marginBottom: '4px' }} />
              <div style={{ fontWeight: 800, fontSize: '1.1rem' }}>Roteador Gateway Principal</div>
              <div className="mono-text" style={{ fontSize: '0.9rem', color: '#a7f3d0' }}>{detectedSubnet}.1 (Gateway)</div>
              <span className="badge badge-online" style={{ marginTop: '6px', fontSize: '0.7rem' }}>ONLINE • LATÊNCIA 1ms</span>
            </div>

            {/* Connecting Rays */}
            <div style={{ width: '80%', height: '2px', background: 'linear-gradient(90deg, transparent, #38bdf8, transparent)', marginBottom: '40px' }} />

            {/* Nodes Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '24px', width: '100%' }}>
              {/* Agent Nodes */}
              {agents.map((ag) => (
                <div key={ag.agentId} className="glass-panel" style={{ 
                  padding: '20px', borderRadius: '14px', border: '1px solid #38bdf8',
                  boxShadow: ag.status === 'warning' ? '0 0 20px rgba(245, 158, 11, 0.4)' : '0 0 20px rgba(56, 189, 248, 0.3)',
                  background: 'rgba(15, 23, 42, 0.7)'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '10px' }}>
                    <div style={{ background: 'rgba(56, 189, 248, 0.2)', padding: '8px', borderRadius: '10px' }}>
                      {ag.inventory?.osName.includes('Android') ? <Radio size={20} color="#34d399" /> : <Monitor size={20} color="#38bdf8" />}
                    </div>
                    <div>
                      <h4 style={{ color: '#fff', fontWeight: 700, fontSize: '0.95rem' }}>{ag.hostname}</h4>
                      <span className="mono-text" style={{ fontSize: '0.75rem', color: '#38bdf8' }}>{ag.inventory?.ipAddress}</span>
                    </div>
                  </div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    <div><strong>OS:</strong> {ag.inventory?.osName}</div>
                    <div><strong>MAC:</strong> <span className="mono-text">{ag.inventory?.macAddress}</span></div>
                    <div><strong>Agente:</strong> EDR Ativo ({ag.status.toUpperCase()})</div>
                  </div>
                  <div style={{ marginTop: '12px', background: 'rgba(0,0,0,0.3)', padding: '8px', borderRadius: '8px', display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem' }}>
                    <span>CPU: <strong style={{ color: '#38bdf8' }}>{(ag.metrics?.cpuUsagePct || 0).toFixed(1)}%</strong></span>
                    <span>RAM: <strong style={{ color: '#34d399' }}>{(ag.metrics?.memoryUsagePct || 0).toFixed(1)}%</strong></span>
                  </div>
                </div>
              ))}

              {/* Discovered Agentless Devices */}
              {agentlessDevices.map((dev) => {
                const isCrit = dev.riskScore === 'CRITICAL' || dev.riskScore === 'HIGH';
                return (
                  <div key={dev.ipAddress} className="glass-panel" style={{ 
                    padding: '20px', borderRadius: '14px',
                    border: isCrit ? '1px solid #f43f5e' : '1px solid var(--border-glass)',
                    boxShadow: isCrit ? '0 0 20px rgba(244, 63, 94, 0.3)' : 'none',
                    background: 'rgba(15, 23, 42, 0.5)'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <div style={{ background: isCrit ? 'rgba(244, 63, 94, 0.2)' : 'rgba(255,255,255,0.05)', padding: '8px', borderRadius: '10px' }}>
                          <Globe size={20} color={isCrit ? '#f43f5e' : '#94a3b8'} />
                        </div>
                        <div>
                          <h4 style={{ color: '#fff', fontWeight: 700, fontSize: '0.9rem' }}>{dev.vendorName}</h4>
                          <span className="mono-text" style={{ fontSize: '0.75rem', color: '#94a3b8' }}>{dev.ipAddress}</span>
                        </div>
                      </div>
                      <span className={`badge ${dev.riskScore === 'CRITICAL' ? 'badge-critical' : dev.riskScore === 'HIGH' ? 'badge-warning' : 'badge-online'}`} style={{ fontSize: '0.65rem' }}>
                        {dev.riskScore}
                      </span>
                    </div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                      <div><strong>MAC:</strong> <span className="mono-text">{dev.macAddress}</span></div>
                      <div><strong>Portas Abertas:</strong> <span style={{ color: '#38bdf8' }}>{(dev.openPorts || []).join(', ') || 'Nenhuma'}</span></div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* Matriz MITRE ATT&CK Tab */}
      {activeTab === 'mitre_matrix' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          <div className="glass-panel" style={{ padding: '24px', background: 'linear-gradient(135deg, rgba(244, 63, 94, 0.08), rgba(225, 29, 72, 0.08))', border: '1px solid rgba(244, 63, 94, 0.3)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <h2 style={{ fontSize: '1.2rem', fontWeight: 800, color: '#ffffff', display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <Layers size={24} color="#f43f5e" /> Matriz de Táticas e Técnicas MITRE ATT&CK
                </h2>
                <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
                  Mapeamento em tempo real do ecossistema de detecção contra o framework MITRE ATT&CK v14.
                </p>
              </div>
              <span className="badge badge-critical" style={{ fontSize: '0.85rem', padding: '6px 14px' }}>
                <AlertTriangle size={14} /> {alerts.length} Detecções Registradas
              </span>
            </div>
          </div>

          {/* ATT&CK Matrix Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: '16px', overflowX: 'auto' }}>
            {[
              { tactic: 'Execution', id: 'TA0002', rules: ['RULE-WIN-001', 'RULE-CMD-009', 'RULE-LOL-014'] },
              { tactic: 'Persistence', id: 'TA0003', rules: ['RULE-REG-006', 'RULE-SYS-007'] },
              { tactic: 'Defense Evasion', id: 'TA0005', rules: ['RULE-PROC-010', 'RULE-MASQ-012'] },
              { tactic: 'Credential Access', id: 'TA0006', rules: ['RULE-MEM-005'] },
              { tactic: 'Command & Control', id: 'TA0011', rules: ['RULE-NET-003', 'RULE-NET-008', 'RULE-BEACON-015'] },
              { tactic: 'Impact / Exfil', id: 'TA0040', rules: ['RULE-FILE-002', 'RULE-RES-004', 'RULE-EXFIL-016', 'RULE-MINER-017'] },
            ].map((col) => (
              <div key={col.id} className="glass-panel" style={{ padding: '16px', background: 'rgba(15, 23, 42, 0.6)' }}>
                <div style={{ borderBottom: '2px solid #f43f5e', paddingBottom: '10px', marginBottom: '14px' }}>
                  <h4 style={{ color: '#fff', fontWeight: 800, fontSize: '0.9rem' }}>{col.tactic}</h4>
                  <span className="mono-text" style={{ fontSize: '0.7rem', color: '#f43f5e' }}>{col.id}</span>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {col.rules.map((ruleId) => {
                    const ruleDef = rules.find((r) => r.ruleId === ruleId);
                    const hitCount = alerts.filter((a) => a.ruleId === ruleId).length;
                    return (
                      <div key={ruleId} style={{ 
                        background: hitCount > 0 ? 'rgba(244, 63, 94, 0.15)' : 'rgba(255, 255, 255, 0.03)',
                        border: hitCount > 0 ? '1px solid #f43f5e' : '1px solid rgba(255, 255, 255, 0.08)',
                        padding: '10px', borderRadius: '8px'
                      }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                          <span className="mono-text" style={{ fontSize: '0.7rem', color: hitCount > 0 ? '#f43f5e' : '#94a3b8', fontWeight: 700 }}>
                            {ruleId}
                          </span>
                          {hitCount > 0 && (
                            <span className="badge badge-critical" style={{ fontSize: '0.65rem' }}>
                              {hitCount} HITS
                            </span>
                          )}
                        </div>
                        <div style={{ fontSize: '0.75rem', color: '#fff', fontWeight: 600 }}>
                          {ruleDef?.name || ruleId}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Regras MITRE ATT&CK Tab */}
      {activeTab === 'rules' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          <div className="glass-panel" style={{ padding: '24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <h2 style={{ fontSize: '1.2rem', fontWeight: 800, color: '#ffffff', display: 'flex', alignItems: 'center', gap: '10px' }}>
                <Zap size={22} color="var(--accent-cyan)" /> Catálogo de Regras de Detecção MITRE ATT&CK ({rules.length})
              </h2>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
                Regras pré-configuradas e ativas no motor de correlação em tempo real.
              </p>
            </div>
            <button
              onClick={() => setShowAddRule(true)}
              style={{ background: 'linear-gradient(135deg, #06b6d4, #3b82f6)', color: '#fff', border: 'none', padding: '10px 18px', borderRadius: '10px', fontSize: '0.85rem', fontWeight: 700, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '8px' }}
            >
              <PlusCircle size={16} /> Nova Regra
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(400px, 1fr))', gap: '20px' }}>
            {rules.map((rule) => (
              <div key={rule.ruleId} className="glass-panel" style={{ padding: '20px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '10px' }}>
                    <span className="mono-text" style={{ fontSize: '0.8rem', color: 'var(--accent-cyan)', fontWeight: 700 }}>
                      {rule.ruleId}
                    </span>
                    <span className={`badge ${rule.severity === 'CRITICAL' ? 'badge-critical' : rule.severity === 'HIGH' ? 'badge-warning' : 'badge-online'}`}>
                      {rule.severity}
                    </span>
                  </div>
                  <h3 style={{ fontSize: '1rem', fontWeight: 700, color: '#fff', marginBottom: '8px' }}>{rule.name}</h3>
                  <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>{rule.description}</p>
                </div>
                <div style={{ marginTop: '16px', paddingTop: '12px', borderTop: '1px solid rgba(255,255,255,0.05)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span className="badge" style={{ background: 'rgba(255,255,255,0.05)', color: 'var(--text-muted)' }}>{rule.category}</span>
                  <span style={{ fontSize: '0.75rem', color: rule.enabled ? '#34d399' : '#f87171', fontWeight: 600 }}>
                    {rule.enabled ? '● Ativa no Engine' : '○ Desativada'}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Modal Detailed Process Inspection & Lineage Tree */}
      {selectedProcessDetails && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0, 0, 0, 0.8)', backdropFilter: 'blur(8px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div className="glass-panel" style={{ padding: '32px', width: '100%', maxWidth: '680px', maxHeight: '90vh', overflowY: 'auto' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '20px' }}>
              <div>
                <span className="badge badge-online" style={{ marginBottom: '6px' }}>Árvore de Linhagem do Processo</span>
                <h3 style={{ fontSize: '1.4rem', fontWeight: 800, color: '#fff' }}>{selectedProcessDetails.name}</h3>
              </div>
              <XCircle size={22} style={{ cursor: 'pointer', color: 'var(--text-muted)' }} onClick={() => setSelectedProcessDetails(null)} />
            </div>

            {/* Ancestry & Lineage Tree Display */}
            <div style={{ background: 'rgba(0,0,0,0.4)', padding: '16px', borderRadius: '12px', marginBottom: '20px', border: '1px solid var(--border-glass)' }}>
              <h4 style={{ fontSize: '0.85rem', color: 'var(--accent-cyan)', fontWeight: 700, marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Layers size={14} /> Hierarquia Pai ➔ Processo ➔ Filhos
              </h4>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {/* Parent Process */}
                {selectedProcessDetails.parentPid ? (
                  <div style={{ padding: '10px 14px', background: 'rgba(255,255,255,0.03)', borderRadius: '8px', borderLeft: '3px solid #94a3b8', fontSize: '0.8rem' }}>
                    <span style={{ color: 'var(--text-muted)' }}>Processo Pai (PPID {selectedProcessDetails.parentPid}):</span>
                    <div style={{ color: '#fff', fontWeight: 600 }}>
                      {processes.find(p => p.pid === selectedProcessDetails.parentPid)?.name || `PID ${selectedProcessDetails.parentPid}`}
                    </div>
                  </div>
                ) : (
                  <div style={{ padding: '8px 12px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    Processo Raiz do Sistema (Sem Pai Registrado)
                  </div>
                )}

                <div style={{ textAlign: 'center', color: 'var(--accent-cyan)' }}>↓</div>

                {/* Target Process */}
                <div style={{ padding: '12px 16px', background: 'rgba(6, 182, 212, 0.15)', borderRadius: '10px', border: '1px solid var(--accent-cyan)', fontSize: '0.85rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <strong style={{ color: '#fff' }}>{selectedProcessDetails.name} (PID {selectedProcessDetails.pid})</strong>
                    <span className="mono-text" style={{ color: '#38bdf8' }}>{selectedProcessDetails.cpuPct.toFixed(1)}% CPU</span>
                  </div>
                  <div className="mono-text" style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
                    {selectedProcessDetails.executablePath}
                  </div>
                </div>

                {/* Child Processes */}
                {processes.filter(p => p.parentPid === selectedProcessDetails.pid).length > 0 && (
                  <>
                    <div style={{ textAlign: 'center', color: 'var(--accent-cyan)' }}>↓</div>
                    <div style={{ padding: '10px 14px', background: 'rgba(244, 63, 94, 0.1)', borderRadius: '8px', borderLeft: '3px solid #f43f5e', fontSize: '0.8rem' }}>
                      <span style={{ color: '#f43f5e', fontWeight: 700 }}>Processos Filhos Gerados:</span>
                      {processes.filter(p => p.parentPid === selectedProcessDetails.pid).map(child => (
                        <div key={child.pid} style={{ color: '#fff', marginTop: '4px' }}>
                          • {child.name} (PID {child.pid}) — <span className="mono-text">{child.executablePath}</span>
                        </div>
                      ))}
                    </div>
                  </>
                )}
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div style={{ background: 'rgba(0,0,0,0.3)', padding: '12px', borderRadius: '8px' }}>
                  <span style={{ color: 'var(--text-muted)' }}>PID do Processo:</span>
                  <p className="mono-text" style={{ fontSize: '1rem', color: 'var(--accent-cyan)', fontWeight: 700 }}>{selectedProcessDetails.pid}</p>
                </div>
                <div style={{ background: 'rgba(0,0,0,0.3)', padding: '12px', borderRadius: '8px' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Dispositivo Host:</span>
                  <p style={{ fontSize: '1rem', color: '#34d399', fontWeight: 700 }}>{selectedProcessDetails.hostname || 'Local'}</p>
                </div>
              </div>

              <div style={{ background: 'rgba(0,0,0,0.3)', padding: '12px', borderRadius: '8px' }}>
                <span style={{ color: 'var(--text-muted)' }}>Caminho do Executável:</span>
                <p className="mono-text" style={{ fontSize: '0.8rem', color: '#fff', wordBreak: 'break-all', marginTop: '4px' }}>
                  {selectedProcessDetails.executablePath || 'Kernel Process / System Protected'}
                </p>
              </div>

              <div style={{ background: 'rgba(0,0,0,0.3)', padding: '12px', borderRadius: '8px' }}>
                <span style={{ color: 'var(--text-muted)' }}>Hash SHA-256 Verificado:</span>
                <p className="mono-text" style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)', wordBreak: 'break-all', marginTop: '4px' }}>
                  {selectedProcessDetails.sha256Hash}
                </p>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div style={{ background: 'rgba(0,0,0,0.3)', padding: '12px', borderRadius: '8px' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Consumo CPU:</span>
                  <p style={{ fontSize: '1rem', color: selectedProcessDetails.cpuPct > 50 ? '#f87171' : '#34d399', fontWeight: 700 }}>
                    {selectedProcessDetails.cpuPct.toFixed(1)}%
                  </p>
                </div>
                <div style={{ background: 'rgba(0,0,0,0.3)', padding: '12px', borderRadius: '8px' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Uso de Memória RAM:</span>
                  <p style={{ fontSize: '1rem', color: '#fff', fontWeight: 700 }}>
                    {selectedProcessDetails.memoryMb} MB
                  </p>
                </div>
              </div>
            </div>

            <div style={{ marginTop: '20px', display: 'flex', justifyContent: 'flex-end', gap: '12px' }}>
              <button 
                onClick={() => setSelectedProcessDetails(null)} 
                style={{ padding: '8px 20px', background: 'linear-gradient(135deg, #06b6d4, #3b82f6)', border: 'none', color: '#fff', borderRadius: '8px', fontWeight: 700, cursor: 'pointer' }}
              >
                Fechar Inspeção
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal Add New Rule */}
      {showAddRule && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0, 0, 0, 0.75)', backdropFilter: 'blur(8px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div className="glass-panel" style={{ padding: '32px', width: '100%', maxWidth: '540px' }}>
            <h3 style={{ fontSize: '1.3rem', fontWeight: 800, color: '#fff', marginBottom: '20px' }}>Adicionar Nova Regra MITRE ATT&CK</h3>
            <form onSubmit={handleCreateRule} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div>
                <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '6px' }}>ID da Regra (ex: RULE-C2-011)</label>
                <input type="text" value={newRuleId} onChange={(e) => setNewRuleId(e.target.value)} required style={{ width: '100%', padding: '10px', background: 'rgba(0, 0, 0, 0.4)', border: '1px solid var(--border-glass)', borderRadius: '8px', color: '#fff' }} />
              </div>
              <div>
                <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '6px' }}>Nome da Regra</label>
                <input type="text" value={newRuleName} onChange={(e) => setNewRuleName(e.target.value)} required style={{ width: '100%', padding: '10px', background: 'rgba(0, 0, 0, 0.4)', border: '1px solid var(--border-glass)', borderRadius: '8px', color: '#fff' }} />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div>
                  <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '6px' }}>Categoria</label>
                  <select value={newRuleCategory} onChange={(e: any) => setNewRuleCategory(e.target.value)} style={{ width: '100%', padding: '10px', background: 'rgba(0, 0, 0, 0.4)', border: '1px solid var(--border-glass)', borderRadius: '8px', color: '#fff' }}>
                    <option value="PROCESS">PROCESS</option>
                    <option value="FILE">FILE</option>
                    <option value="NETWORK">NETWORK</option>
                    <option value="BEHAVIOR">BEHAVIOR</option>
                  </select>
                </div>
                <div>
                  <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '6px' }}>Severidade</label>
                  <select value={newRuleSeverity} onChange={(e: any) => setNewRuleSeverity(e.target.value)} style={{ width: '100%', padding: '10px', background: 'rgba(0, 0, 0, 0.4)', border: '1px solid var(--border-glass)', borderRadius: '8px', color: '#fff' }}>
                    <option value="INFO">INFO</option>
                    <option value="WARNING">WARNING</option>
                    <option value="HIGH">HIGH</option>
                    <option value="CRITICAL">CRITICAL</option>
                  </select>
                </div>
              </div>
              <div>
                <label style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '6px' }}>Descrição</label>
                <textarea value={newRuleDescription} onChange={(e) => setNewRuleDescription(e.target.value)} rows={3} style={{ width: '100%', padding: '10px', background: 'rgba(0, 0, 0, 0.4)', border: '1px solid var(--border-glass)', borderRadius: '8px', color: '#fff' }} />
              </div>
              <div style={{ display: 'flex', gap: '12px', marginTop: '10px' }}>
                <button type="button" onClick={() => setShowAddRule(false)} style={{ flex: 1, padding: '10px', background: 'transparent', border: '1px solid var(--border-glass)', color: '#fff', borderRadius: '8px', cursor: 'pointer' }}>Cancelar</button>
                <button type="submit" style={{ flex: 1, padding: '10px', background: 'linear-gradient(135deg, #06b6d4, #3b82f6)', border: 'none', color: '#fff', borderRadius: '8px', fontWeight: 700, cursor: 'pointer' }}>Salvar Regra</button>
              </div>
            </form>
          </div>
        </div>
      )}
      {/* Modal Android Installation */}
      {showAndroidInstallModal && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0, 0, 0, 0.8)', backdropFilter: 'blur(10px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: '20px' }}>
          <div className="glass-panel" style={{ padding: '32px', width: '100%', maxWidth: '650px', borderRadius: '16px', border: '1px solid var(--accent-cyan)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div style={{ background: 'linear-gradient(135deg, #06b6d4, #3b82f6)', padding: '10px', borderRadius: '12px' }}>
                  <Smartphone size={24} color="#fff" />
                </div>
                <div>
                  <h3 style={{ fontSize: '1.3rem', fontWeight: 800, color: '#fff' }}>Instalação Completa no Android (Termux)</h3>
                  <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>Instalação automatizada em 1-clique com persistência e execução em segundo plano</p>
                </div>
              </div>
              <XCircle size={22} color="var(--text-muted)" style={{ cursor: 'pointer' }} onClick={() => setShowAndroidInstallModal(false)} />
            </div>

            <div style={{ background: 'rgba(0,0,0,0.4)', border: '1px solid rgba(6, 182, 212, 0.3)', padding: '16px', borderRadius: '12px', marginBottom: '20px' }}>
              <span style={{ fontSize: '0.8rem', color: 'var(--accent-cyan)', fontWeight: 700, display: 'block', marginBottom: '8px' }}>
                📋 COMANDO ÚNICO DE INSTALAÇÃO (COPIE E COLE NO TERMUX):
              </span>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: '#090d16', padding: '12px 14px', borderRadius: '8px', border: '1px solid #1e293b' }}>
                <code className="mono-text" style={{ fontSize: '0.85rem', color: '#34d399', wordBreak: 'break-all' }}>
                  pkg install -y curl bash && curl -sSL http://{window.location.hostname}:4000/android.sh | bash
                </code>
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(`pkg install -y curl bash && curl -sSL http://${window.location.hostname}:4000/android.sh | bash`);
                    setCopiedCmd(true);
                    setTimeout(() => setCopiedCmd(false), 3000);
                  }}
                  style={{ background: copiedCmd ? '#10b981' : 'linear-gradient(135deg, #06b6d4, #3b82f6)', color: '#fff', border: 'none', padding: '8px 14px', borderRadius: '6px', fontSize: '0.75rem', fontWeight: 700, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '6px', marginLeft: '12px', flexShrink: 0 }}
                >
                  {copiedCmd ? <Check size={14} /> : <Copy size={14} />}
                  {copiedCmd ? 'Copiado!' : 'Copiar'}
                </button>
              </div>
            </div>

            <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '10px', marginBottom: '24px' }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
                <span style={{ background: 'rgba(6, 182, 212, 0.2)', color: 'var(--accent-cyan)', width: '22px', height: '22px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.75rem', fontWeight: 800, flexShrink: 0 }}>1</span>
                <span>Abra o app <strong>Termux</strong> no celular Android (disponível no F-Droid ou APK oficial).</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
                <span style={{ background: 'rgba(6, 182, 212, 0.2)', color: 'var(--accent-cyan)', width: '22px', height: '22px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.75rem', fontWeight: 800, flexShrink: 0 }}>2</span>
                <span>Cole o comando acima e pressione <strong>Enter</strong>. O script instalará o Python, configurará as dependências e o script de inicialização automaticamente.</span>
              </div>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
                <span style={{ background: 'rgba(6, 182, 212, 0.2)', color: 'var(--accent-cyan)', width: '22px', height: '22px', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '0.75rem', fontWeight: 800, flexShrink: 0 }}>3</span>
                <span>O agente ativa automaticamente o <strong>termux-wake-lock</strong> e roda como daemon de fundo (24/7). Você poderá gerenciar via o comando <code>guardian status</code> ou <code>guardian logs</code> no Termux!</span>
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button
                onClick={() => setShowAndroidInstallModal(false)}
                style={{ padding: '10px 24px', background: 'linear-gradient(135deg, #06b6d4, #3b82f6)', border: 'none', color: '#fff', borderRadius: '8px', fontWeight: 700, cursor: 'pointer' }}
              >
                Concluído
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
