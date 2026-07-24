# GUARDIAN EDR PLATFORM 🛡️
## Volume 5 — Guardian Database — Modelagem & Arquitetura de Persistência
**Versão:** 1.0.0  
**Tecnologia:** PostgreSQL 16 + Redis  
**Status:** Especificação Técnica de Engenharia  

---

## 📑 Sumário

1. [Capítulo 1 — Escolha de Armazenamento Relacional & Cache](#capítulo-1--escolha-de-armazenamento-relacional--cache)
2. [Capítulo 2 — Esquema DDL do Banco de Dados](#capítulo-2--esquema-ddl-do-banco-de-dados)
3. [Capítulo 3 — Estratégia de Indexação](#capítulo-3--estratégia-de-indexação)
4. [Capítulo 4 — Retenção de Dados & Limpeza Automática (Pruning)](#capítulo-4--retenção-de-dados--limpeza-automática-pruning)

---

## Capítulo 1 — Escolha de Armazenamento Relacional & Cache

O **Guardian EDR** utiliza um modelo de armazenamento híbrido de alto desempenho:
- **Redis (Em Memória):** Mantém o estado atualizado do batimento cardíaco (*heartbeat*) e métricas recentes dos agentes com tempo de expiração curto (TTL 90s).
- **PostgreSQL 16 (Relacional Persistente):** Armazena a estrutura permanente de agentes, processos, inventários de hardware, conexões de rede, regras e alertas.

---

## Capítulo 2 — Esquema DDL do Banco de Dados

```sql
-- 1. Tabela de Agentes Registrados
CREATE TABLE agents (
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

-- 2. Tabela de Processos Telemétricos
CREATE TABLE process_telemetry (
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

-- 3. Tabela de Sockets de Rede
CREATE TABLE network_sockets (
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

-- 4. Tabela de Alertas de Ameaças Disparados
CREATE TABLE alerts (
    alert_id VARCHAR(64) PRIMARY KEY,
    agent_id VARCHAR(64) REFERENCES agents(agent_id),
    rule_id VARCHAR(64) NOT NULL,
    rule_name VARCHAR(128) NOT NULL,
    severity VARCHAR(32) NOT NULL,
    details TEXT,
    status VARCHAR(32) DEFAULT 'ACTIVE',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

---

## Capítulo 3 — Estratégia de Indexação

Para garantir que o Dashboard e a API executem buscas em milissegundos:

```sql
CREATE INDEX idx_process_agent_time ON process_telemetry(agent_id, captured_at DESC);
CREATE INDEX idx_process_sha256 ON process_telemetry(sha256_hash);
CREATE INDEX idx_network_agent_time ON network_sockets(agent_id, captured_at DESC);
CREATE INDEX idx_alerts_status ON alerts(status, severity);
```

---

## Capítulo 4 — Retenção de Dados & Limpeza Automática (Pruning)

Eventos de telemetria rotineiros (como leituras de sockets normais) são expurgados automaticamente após **30 dias** por uma procedure agendada (`pg_cron`), enquanto eventos categorizados como `ALERT` ou `SECURITY` são mantidos por **365 dias** para fins de auditoria e *Threat Hunting*.
