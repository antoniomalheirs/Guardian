import pg from 'pg';
import fs from 'fs';
import path from 'path';
import { 
  AgentRecord, 
  EDRAlert, 
  EDREvent, 
  FileTelemetry, 
  NetworkTelemetry, 
  ProcessTelemetry, 
  RuleDefinition, 
  SystemInventory, 
  TelemetryPayload 
} from './types.js';

const { Pool } = pg;

// PostgreSQL Connection Config from Environment or default localhost
const DATABASE_URL = process.env.DATABASE_URL || 'postgres://postgres:postgres@localhost:5432/guardian_edr';

let pool: pg.Pool | null = null;
let isPostgresConnected = false;
const STORAGE_FILE = path.join(process.cwd(), 'storage.json');

// Initialize Database connection and auto-create tables
export async function initDatabase(): Promise<boolean> {
  try {
    pool = new Pool({
      connectionString: DATABASE_URL,
      connectionTimeoutMillis: 3000,
    });

    const client = await pool.connect();
    console.log('🐘 Connected to PostgreSQL Database Server successfully!');
    isPostgresConnected = true;

    // Create DDL Tables
    await client.query(`
      CREATE TABLE IF NOT EXISTS agents (
        agent_id VARCHAR(64) PRIMARY KEY,
        hostname VARCHAR(128) NOT NULL,
        os_name VARCHAR(128) NOT NULL,
        os_version VARCHAR(64),
        architecture VARCHAR(32),
        cpu_model VARCHAR(128),
        total_memory_mb INT,
        ip_address VARCHAR(45),
        status VARCHAR(32) DEFAULT 'online',
        last_heartbeat TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS process_telemetry (
        id BIGSERIAL PRIMARY KEY,
        agent_id VARCHAR(64) REFERENCES agents(agent_id) ON DELETE CASCADE,
        pid INT NOT NULL,
        parent_pid INT,
        name VARCHAR(128) NOT NULL,
        executable_path TEXT,
        cpu_pct REAL,
        memory_mb INT,
        sha256_hash VARCHAR(64),
        captured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS network_sockets (
        id BIGSERIAL PRIMARY KEY,
        agent_id VARCHAR(64) REFERENCES agents(agent_id) ON DELETE CASCADE,
        pid INT NOT NULL,
        process_name VARCHAR(128),
        protocol VARCHAR(16),
        local_address VARCHAR(45),
        local_port INT,
        remote_address VARCHAR(45),
        remote_port INT,
        status VARCHAR(32),
        captured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS file_events (
        id BIGSERIAL PRIMARY KEY,
        agent_id VARCHAR(64) REFERENCES agents(agent_id) ON DELETE CASCADE,
        file_path TEXT NOT NULL,
        action VARCHAR(32) NOT NULL,
        file_size_bytes BIGINT,
        captured_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS alerts (
        alert_id VARCHAR(64) PRIMARY KEY,
        agent_id VARCHAR(64) REFERENCES agents(agent_id) ON DELETE CASCADE,
        hostname VARCHAR(128),
        rule_id VARCHAR(64) NOT NULL,
        rule_name VARCHAR(128) NOT NULL,
        severity VARCHAR(32) NOT NULL,
        details TEXT,
        status VARCHAR(32) DEFAULT 'ACTIVE',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);

    client.release();
    console.log('✅ PostgreSQL DDL Tables Verified / Initialized.');
    return true;
  } catch (err) {
    console.warn('⚠️ Could not connect to external PostgreSQL server. Operating with File Persistence mode (storage.json).');
    isPostgresConnected = false;
    return false;
  }
}

export function isDbConnected(): boolean {
  return isPostgresConnected;
}

// Database Operations
export async function saveAgentToDb(agent: AgentRecord) {
  if (!isPostgresConnected || !pool) return;
  try {
    await pool.query(
      `INSERT INTO agents (agent_id, hostname, os_name, os_version, architecture, cpu_model, total_memory_mb, ip_address, status, last_heartbeat)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
       ON CONFLICT (agent_id) DO UPDATE SET
         status = EXCLUDED.status,
         last_heartbeat = EXCLUDED.last_heartbeat,
         ip_address = EXCLUDED.ip_address`,
      [
        agent.agentId,
        agent.hostname,
        agent.inventory.osName,
        agent.inventory.osVersion,
        agent.inventory.architecture,
        agent.inventory.cpuModel,
        agent.inventory.totalMemoryMb,
        agent.inventory.ipAddress,
        agent.status,
        agent.lastHeartbeat,
      ]
    );
  } catch (err) {
    console.error('Error saving agent to Postgres:', err);
  }
}

export async function saveTelemetryToDb(agentId: string, payload: TelemetryPayload) {
  if (!isPostgresConnected || !pool) return;
  try {
    // Insert Process Telemetry
    if (payload.topProcesses) {
      for (const p of payload.topProcesses) {
        await pool.query(
          `INSERT INTO process_telemetry (agent_id, pid, parent_pid, name, executable_path, cpu_pct, memory_mb, sha256_hash)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
          [agentId, p.pid, p.parentPid || null, p.name, p.executablePath, p.cpuPct, p.memoryMb, p.sha256Hash]
        );
      }
    }

    // Insert Network Telemetry
    if (payload.networkConnections) {
      for (const n of payload.networkConnections) {
        await pool.query(
          `INSERT INTO network_sockets (agent_id, pid, process_name, protocol, local_address, local_port, remote_address, remote_port, status)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
          [agentId, n.pid, n.processName, n.protocol, n.localAddress, n.localPort, n.remoteAddress, n.remotePort, n.status]
        );
      }
    }

    // Insert File Events
    if (payload.fileEvents) {
      for (const f of payload.fileEvents) {
        await pool.query(
          `INSERT INTO file_events (agent_id, file_path, action, file_size_bytes)
           VALUES ($1, $2, $3, $4)`,
          [agentId, f.filePath, f.action, f.fileSizeBytes]
        );
      }
    }
  } catch (err) {
    console.error('Error saving telemetry to Postgres:', err);
  }
}

export async function saveAlertToDb(alert: EDRAlert) {
  if (!isPostgresConnected || !pool) return;
  try {
    await pool.query(
      `INSERT INTO alerts (alert_id, agent_id, hostname, rule_id, rule_name, severity, details, status, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       ON CONFLICT (alert_id) DO UPDATE SET status = EXCLUDED.status`,
      [alert.alertId, alert.agentId, alert.hostname, alert.ruleId, alert.ruleName, alert.severity, alert.details, alert.status, alert.timestamp]
    );
  } catch (err) {
    console.error('Error saving alert to Postgres:', err);
  }
}
