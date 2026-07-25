"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.initDatabase = initDatabase;
exports.isDbConnected = isDbConnected;
exports.saveAgentToDb = saveAgentToDb;
exports.deleteAgentFromDb = deleteAgentFromDb;
exports.loadAgentsFromDb = loadAgentsFromDb;
exports.saveDiscoveredDevicesToDb = saveDiscoveredDevicesToDb;
exports.loadDiscoveredDevicesFromDb = loadDiscoveredDevicesFromDb;
exports.saveTelemetryToDb = saveTelemetryToDb;
exports.saveAlertToDb = saveAlertToDb;
const sqlite3_1 = __importDefault(require("sqlite3"));
const path_1 = __importDefault(require("path"));
const DB_PATH = path_1.default.join(process.cwd(), 'guardian.db');
let db;
async function initDatabase() {
    return new Promise((resolve, reject) => {
        db = new sqlite3_1.default.Database(DB_PATH, (err) => {
            if (err) {
                console.error('❌ Error connecting to SQLite database:', err);
                return reject(err);
            }
            console.log(`🗄️ Connected to SQLite Database at ${DB_PATH}`);
            createTables().then(resolve).catch(reject);
        });
    });
}
function createTables() {
    return new Promise((resolve, reject) => {
        db.serialize(() => {
            db.run(`
        CREATE TABLE IF NOT EXISTS agents (
          agent_id TEXT PRIMARY KEY,
          hostname TEXT NOT NULL,
          status TEXT NOT NULL,
          inventory TEXT NOT NULL,
          last_heartbeat TEXT NOT NULL,
          metrics TEXT NOT NULL,
          updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);
            db.run(`
        CREATE TABLE IF NOT EXISTS discovered_devices (
          ip_address TEXT PRIMARY KEY,
          mac_address TEXT NOT NULL,
          vendor_name TEXT NOT NULL,
          device_type TEXT NOT NULL,
          open_ports TEXT NOT NULL,
          risk_score TEXT NOT NULL,
          detected_threats TEXT NOT NULL,
          last_seen TEXT NOT NULL
        )
      `);
            db.run(`
        CREATE TABLE IF NOT EXISTS process_telemetry (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          agent_id TEXT NOT NULL,
          pid INTEGER NOT NULL,
          parent_pid INTEGER,
          name TEXT NOT NULL,
          executable_path TEXT NOT NULL,
          cpu_pct REAL NOT NULL,
          memory_mb INTEGER NOT NULL,
          sha256_hash TEXT NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);
            db.run(`
        CREATE TABLE IF NOT EXISTS network_telemetry (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          agent_id TEXT NOT NULL,
          pid INTEGER NOT NULL,
          process_name TEXT NOT NULL,
          protocol TEXT NOT NULL,
          local_address TEXT NOT NULL,
          local_port INTEGER NOT NULL,
          remote_address TEXT NOT NULL,
          remote_port INTEGER NOT NULL,
          status TEXT NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);
            db.run(`
        CREATE TABLE IF NOT EXISTS file_telemetry (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          agent_id TEXT NOT NULL,
          file_path TEXT NOT NULL,
          action TEXT NOT NULL,
          file_size_bytes INTEGER NOT NULL,
          timestamp TEXT NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
      `);
            db.run(`
        CREATE INDEX IF NOT EXISTS idx_process_agent_created ON process_telemetry(agent_id, created_at DESC)
      `);
            db.run(`
        CREATE INDEX IF NOT EXISTS idx_network_agent_created ON network_telemetry(agent_id, created_at DESC)
      `);
            db.run(`
        CREATE INDEX IF NOT EXISTS idx_file_agent_created ON file_telemetry(agent_id, created_at DESC)
      `);
            db.run(`
        CREATE TABLE IF NOT EXISTS alerts (
          alert_id TEXT PRIMARY KEY,
          agent_id TEXT NOT NULL,
          hostname TEXT NOT NULL,
          rule_id TEXT NOT NULL,
          rule_name TEXT NOT NULL,
          severity TEXT NOT NULL,
          timestamp TEXT NOT NULL,
          details TEXT NOT NULL,
          status TEXT NOT NULL
        )
      `, (err) => {
                if (err)
                    return reject(err);
                db.run(`CREATE INDEX IF NOT EXISTS idx_alert_agent_timestamp ON alerts(agent_id, timestamp DESC)`, (idxErr) => {
                    if (idxErr)
                        reject(idxErr);
                    else
                        resolve();
                });
            });
        });
    });
}
function isDbConnected() {
    return !!db;
}
async function saveAgentToDb(agent) {
    if (!db)
        return;
    return new Promise((resolve) => {
        const stmt = db.prepare(`
      INSERT INTO agents (agent_id, hostname, status, inventory, last_heartbeat, metrics, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(agent_id) DO UPDATE SET
        status=excluded.status,
        inventory=excluded.inventory,
        last_heartbeat=excluded.last_heartbeat,
        metrics=excluded.metrics,
        updated_at=CURRENT_TIMESTAMP
    `);
        stmt.run(agent.agentId, agent.hostname, agent.status, JSON.stringify(agent.inventory), agent.lastHeartbeat, JSON.stringify(agent.metrics), () => resolve());
    });
}
async function deleteAgentFromDb(agentId) {
    if (!db)
        return;
    return new Promise((resolve) => {
        db.serialize(() => {
            db.run(`DELETE FROM agents WHERE agent_id = ?`, [agentId]);
            db.run(`DELETE FROM process_telemetry WHERE agent_id = ?`, [agentId]);
            db.run(`DELETE FROM network_telemetry WHERE agent_id = ?`, [agentId]);
            db.run(`DELETE FROM file_telemetry WHERE agent_id = ?`, [agentId]);
            resolve();
        });
    });
}
async function loadAgentsFromDb() {
    if (!db)
        return [];
    return new Promise((resolve) => {
        db.all(`SELECT * FROM agents`, [], (err, rows) => {
            if (err || !rows)
                return resolve([]);
            const agents = rows.map((row) => ({
                agentId: row.agent_id,
                hostname: row.hostname,
                status: row.status,
                inventory: JSON.parse(row.inventory || '{}'),
                lastHeartbeat: row.last_heartbeat,
                metrics: JSON.parse(row.metrics || '{}'),
                topProcesses: [],
                networkConnections: [],
                fileEvents: [],
            }));
            resolve(agents);
        });
    });
}
async function saveDiscoveredDevicesToDb(devices) {
    if (!db || devices.length === 0)
        return;
    return new Promise((resolve) => {
        db.serialize(() => {
            const stmt = db.prepare(`
        INSERT INTO discovered_devices (ip_address, mac_address, vendor_name, device_type, open_ports, risk_score, detected_threats, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ip_address) DO UPDATE SET
          mac_address=excluded.mac_address,
          vendor_name=excluded.vendor_name,
          device_type=excluded.device_type,
          open_ports=excluded.open_ports,
          risk_score=excluded.risk_score,
          detected_threats=excluded.detected_threats,
          last_seen=excluded.last_seen
      `);
            for (const dev of devices) {
                stmt.run(dev.ipAddress, dev.macAddress, dev.vendorName, dev.deviceType, JSON.stringify(dev.openPorts), dev.riskScore, JSON.stringify(dev.detectedThreats), dev.lastSeen);
            }
            stmt.finalize(() => resolve());
        });
    });
}
async function loadDiscoveredDevicesFromDb() {
    if (!db)
        return [];
    return new Promise((resolve) => {
        db.all(`SELECT * FROM discovered_devices ORDER BY ip_address ASC`, [], (err, rows) => {
            if (err || !rows)
                return resolve([]);
            const devices = rows.map((r) => ({
                ipAddress: r.ip_address,
                macAddress: r.mac_address,
                vendorName: r.vendor_name,
                deviceType: r.device_type,
                openPorts: JSON.parse(r.open_ports || '[]'),
                riskScore: r.risk_score,
                detectedThreats: JSON.parse(r.detected_threats || '[]'),
                lastSeen: r.last_seen,
            }));
            resolve(devices);
        });
    });
}
function finalizeStatement(stmt) {
    return new Promise((resolve, reject) => stmt.finalize((err) => err ? reject(err) : resolve()));
}
async function saveTelemetryToDb(agentId, topProcesses, networkConns, fileEvents) {
    if (!db)
        return;
    await new Promise((resolve, reject) => {
        db.serialize(async () => {
            try {
                if (topProcesses && topProcesses.length > 0) {
                    db.run(`DELETE FROM process_telemetry WHERE agent_id = ?`, [agentId]);
                    const pStmt = db.prepare(`
            INSERT INTO process_telemetry (agent_id, pid, parent_pid, name, executable_path, cpu_pct, memory_mb, sha256_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          `);
                    for (const p of topProcesses) {
                        pStmt.run(agentId, p.pid, p.parentPid || null, p.name, p.executablePath || '', p.cpuPct || 0, p.memoryMb || 0, p.sha256Hash || 'N/A');
                    }
                    await finalizeStatement(pStmt);
                }
                if (networkConns && networkConns.length > 0) {
                    db.run(`DELETE FROM network_telemetry WHERE agent_id = ?`, [agentId]);
                    const nStmt = db.prepare(`
            INSERT INTO network_telemetry (agent_id, pid, process_name, protocol, local_address, local_port, remote_address, remote_port, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          `);
                    for (const n of networkConns) {
                        nStmt.run(agentId, n.pid || 0, n.processName || '', n.protocol || 'TCP', n.localAddress || '', n.localPort || 0, n.remoteAddress || '', n.remotePort || 0, n.status || 'ESTABLISHED');
                    }
                    await finalizeStatement(nStmt);
                }
                if (fileEvents && fileEvents.length > 0) {
                    const fStmt = db.prepare(`
            INSERT INTO file_telemetry (agent_id, file_path, action, file_size_bytes, timestamp)
            VALUES (?, ?, ?, ?, ?)
          `);
                    for (const f of fileEvents) {
                        fStmt.run(agentId, f.filePath || '', f.action || 'MODIFIED', f.fileSizeBytes || 0, f.timestamp || new Date().toISOString());
                    }
                    await finalizeStatement(fStmt);
                }
                db.run(`DELETE FROM file_telemetry WHERE created_at < datetime('now', '-30 days')`);
                db.run(`DELETE FROM alerts WHERE timestamp < datetime('now', '-365 days') AND status != 'ACTIVE'`);
                resolve();
            }
            catch (err) {
                reject(err);
            }
        });
    });
}
async function saveAlertToDb(alert) {
    if (!db)
        return;
    return new Promise((resolve) => {
        const stmt = db.prepare(`
      INSERT INTO alerts (alert_id, agent_id, hostname, rule_id, rule_name, severity, timestamp, details, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(alert_id) DO UPDATE SET status=excluded.status
    `);
        stmt.run(alert.alertId, alert.agentId, alert.hostname, alert.ruleId, alert.ruleName, alert.severity, alert.timestamp, alert.details, alert.status, () => resolve());
    });
}
