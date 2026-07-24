# GUARDIAN EDR PLATFORM 🛡️
## Volume 1 — Arquitetura Geral & Especificação Técnica
**Versão:** 1.0.0  
**Status:** Especificação de Engenharia de Software  
**Data:** 2026  

---

## 📑 Sumário

1. [Capítulo 1 — Introdução e Visão do Produto](#capítulo-1--introdução-e-visão-do-produto)
2. [Capítulo 2 — Requisitos Funcionais e Não Funcionais](#capítulo-2--requisitos-funcionais-e-não-funcionais)
3. [Capítulo 3 — Arquitetura do Sistema (Modelo C4)](#capítulo-3--arquitetura-do-sistema-modelo-c4)
4. [Capítulo 4 — Modelo de Comunicação & Contratos de API](#capítulo-4--modelo-de-comunicação--contratos-de-api)
5. [Capítulo 5 — Modelo do Banco de Dados](#capítulo-5--modelo-do-banco-de-dados)
6. [Capítulo 6 — Motor de Regras (Rules Engine)](#capítulo-6--motor-de-regras-rules-engine)
7. [Capítulo 7 — Resposta Automática a Incidentes](#capítulo-7--resposta-automática-a-incidentes)
8. [Capítulo 8 — Roadmap de Evolução (v0.1 a v1.0)](#capítulo-8--roadmap-de-evolução-v01-a-v10)

---

## Capítulo 1 — Introdução e Visão do Produto

### 1.1 Missão
O **Guardian EDR** é uma plataforma modular de *Endpoint Detection and Response* projetada para ambientes corporativos e sistemas gerenciados. Sua finalidade é fornecer:
- **Observabilidade contínua:** Monitoramento de baixo nível sobre processos, conexões de rede, alterações no sistema de arquivos e modificações no registro/serviços.
- **Detecção baseada em comportamento:** Identificação de ameaças conhecidas e desconhecidas (Zero-Day) através do cruzamento e correlação de eventos.
- **Resposta controlada a incidentes:** Execução de ações de mitigação automatizadas ou iniciadas por analistas (ex.: isolamento de host, quarentena de executáveis, encerramento de processos).

### 1.2 Princípios de Arquitetura

```text
┌─────────────────────────────────────────────────────────┐
│                 Filosofia do Guardian                   │
├─────────────────────────────────────────────────────────┤
│  1. Visibilidade antes de Intervenção                   │
│  2. Baixa Pegada de Recursos (RAM < 60MB, CPU < 1%)     │
│  3. Desacoplamento Total via Barramento Interno         │
│  4. Resiliência: Erro num módulo não derruba o Agente   │
└─────────────────────────────────────────────────────────┘
```

---

## Capítulo 2 — Requisitos Funcionais e Não Funcionais

### 2.1 Requisitos Funcionais (RF)

* **RF-01 — Coleta de Inventário:** O agente deve coletar hostname, versão do SO, modelo de CPU, RAM total, endereços IP e MAC no boot e a cada 12 horas.
* **RF-02 — Telemetria de Processos:** Registrar criação, encerramento, árvore de processos pai-filho, PID, hashes (SHA-256) e uso de recursos.
* **RF-03 — Monitoramento do Sistema de Arquivos:** Detectar criação, modificação, renomeação e exclusão em diretórios críticos configurados (`System32`, `Program Files`, diretórios de usuários).
* **RF-04 — Telemetria de Conexões de Rede:** Monitorar conexões ativas TCP/UDP, porta remota, IP remoto e associar a conexão ao PID do processo originador.
* **RF-05 — Heartbeat & Estado:** Enviar sinal de vida a cada 30 segundos contendo métricas de uso de recursos do endpoint.
* **RF-06 — Motor de Regras Centralizado:** Avaliar fluxos de eventos contra regras de correlação (ex.: execução de comandos codificados em Base64 via `powershell.exe`).
* **RF-07 — Console Dashboard em Tempo Real:** Exibir a saúde dos ativos, métricas de CPU/RAM, mapa de endpoints e timeline de alertas de segurança.

### 2.2 Requisitos Não Funcionais (RNF)

* **RNF-01 — Performance do Agente:** Consumo médio de memória RAM $< 60\text{ MB}$ e uso médio de CPU $< 1\%$.
* **RNF-02 — Comunicação Segura:** Todas as trocas de mensagens entre Agente e Servidor Core devem ser autenticadas via Token/mTLS e encriptadas via TLS 1.3.
* **RNF-03 — Tolerância a Falhas:** Se a conexão com o servidor for perdida, o agente deve armazenar temporariamente os eventos numa fila local circular em disco/memória.
* **RNF-04 — Independência de Portas:** O sistema deve operar por padrão na faixa de portas 4000+ (ex.: API Core na porta `4000`, Console Web na porta `4001`).

---

## Capítulo 3 — Arquitetura do Sistema (Modelo C4)

### 3.1 Visão Geral dos Contêineres

```text
                           ┌─────────────────────────┐
                           │    Analista de SOC      │
                           └────────────┬────────────┘
                                        │
                                        ▼ (HTTPS / Port 4001)
                           ┌─────────────────────────┐
                           │    Guardian Console     │
                           │  (React + TS + Vite)    │
                           └────────────┬────────────┘
                                        │
                                        ▼ (REST API / Port 4000)
┌───────────────────────┐  REST / TLS  ┌─────────────────────────┐
│    Guardian Agent     │─────────────►│      Guardian Core      │
│     (Agente Rust)     │              │  (API Server em Node/Go)│
└───────────────────────┘              └────────────┬────────────┘
                                                    │
                                                    ▼
                                       ┌─────────────────────────┐
                                       │    PostgreSQL / Redis   │
                                       └─────────────────────────┘
```

### 3.2 Arquitetura Interna do Agente (Rust)

O **Guardian Agent** utiliza uma arquitetura baseada em ator/canais com o runtime assíncrono `tokio`:

```text
  ┌────────────────────────────────────────────────────────┐
  │                 Monitores de Telemetria                │
  ├──────────────┬──────────────┬───────────┬──────────────┤
  │ ProcessMon   │ FileMon      │ NetMon    │ SysInventory │
  └──────┬───────┴──────┬───────┴─────┬─────┴──────┬───────┘
         │              │             │            │
         ▼              ▼             ▼            ▼
 ┌──────────────────────────────────────────────────────────┐
 │         Barramento Interno (Internal Event Bus)          │
 │             tokio::sync::mpsc::channel                   │
 └──────────────────────────┬───────────────────────────────┘
                            │
                            ▼
 ┌──────────────────────────────────────────────────────────┐
 │                  Fila e Lote de Eventos                  │
 └──────────────────────────┬───────────────────────────────┘
                            │
                            ▼
 ┌──────────────────────────────────────────────────────────┐
 │              Dispatcher (HTTPS POST / JSON)              │
 └──────────────────────────┬───────────────────────────────┘
                            │
                            ▼ (Porta 4000)
                    Guardian Core API
```

---

## Capítulo 4 — Modelo de Comunicação & Contratos de API

### 4.1 Endpoints REST (`Guardian Core API`)

#### 1. Registro de Agente
- **Método:** `POST /api/v1/agents/register`
- **Requisição:**
```json
{
  "hostname": "SENTINEL-PC",
  "osName": "Windows 11 Pro",
  "osVersion": "10.0.22631",
  "architecture": "x64",
  "cpuModel": "AMD Ryzen 7 5700X3D",
  "totalMemoryMb": 32682,
  "ipAddress": "192.168.1.50",
  "macAddress": "00:11:22:33:44:55"
}
```
- **Resposta (`201 Created`):**
```json
{
  "agentId": "agent-sentinelpc-mrzbw6gt",
  "status": "registered"
}
```

#### 2. Batimento Cardíaco (Heartbeat)
- **Método:** `POST /api/v1/agents/heartbeat`
- **Requisição:**
```json
{
  "agentId": "agent-sentinelpc-mrzbw6gt",
  "timestamp": "2026-07-24T19:23:49.120Z",
  "cpuUsagePct": 23.4,
  "memoryUsagePct": 55.2,
  "diskUsagePct": 42.0,
  "activeProcessesCount": 376,
  "eventsCount": 12
}
```
- **Resposta (`200 OK`):**
```json
{
  "status": "acknowledged",
  "nextHeartbeatIntervalSec": 30
}
```

---

## Capítulo 5 — Modelo do Banco de Dados

### 5.1 Tabelas Relacionais Principais

```sql
-- Tabela de Agentes Registrados
CREATE TABLE agents (
    agent_id VARCHAR(64) PRIMARY KEY,
    hostname VARCHAR(128) NOT NULL,
    os_name VARCHAR(128),
    os_version VARCHAR(64),
    architecture VARCHAR(32),
    cpu_model VARCHAR(128),
    total_memory_mb INT,
    ip_address VARCHAR(45),
    status VARCHAR(32) DEFAULT 'online',
    last_heartbeat TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Tabela de Eventos de Telemetria
CREATE TABLE telemetry_events (
    id VARCHAR(64) PRIMARY KEY,
    agent_id VARCHAR(64) REFERENCES agents(agent_id),
    category VARCHAR(32) NOT NULL, -- PROCESS, FILE, NETWORK, SECURITY
    severity VARCHAR(32) NOT NULL, -- INFO, WARNING, HIGH, CRITICAL
    description TEXT NOT NULL,
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

---

## Capítulo 6 — Motor de Regras (Rules Engine)

### 6.1 Estrutura de uma Regra de Detecção

As regras são declarativas e avaliam o fluxo de eventos em tempo real:

```json
{
  "ruleId": "RULE-WIN-001",
  "name": "PowerShell Encoded Command Execution",
  "severity": "HIGH",
  "condition": {
    "category": "PROCESS",
    "processName": "powershell.exe",
    "commandLineContains": ["-EncodedCommand", "-enc"]
  },
  "action": "GENERATE_ALERT"
}
```

---

## Capítulo 7 — Resposta Automática a Incidentes

Quando o motor de regras classifica uma ameaça como `HIGH` ou `CRITICAL`, ações automatizadas podem ser despachadas ao agente:

| Ação | Descrição |
| :--- | :--- |
| `KILL_PROCESS` | Encerra imediatamente o PID malicioso via chamada de sistema. |
| `QUARANTINE_FILE` | Move o arquivo executável para o diretório isolado de quarentena criptografado. |
| `ISOLATE_HOST` | Bloqueia todo o tráfego de rede do endpoint exceto a comunicação com o Guardian Core. |

---

## Capítulo 8 — Roadmap de Evolução (v0.1 a v1.0)

- **v0.1 (MVP - Concluído):** Arquitetura Monorepo, Agente Rust com envio de Heartbeat, API Core Server rodando na porta `4000` e Console Web na porta `4001`.
- **v0.2:** Expansão do Monitor de Processos (Árvore PID e Hashing SHA-256).
- **v0.3:** Monitor de Sistema de Arquivos (File System Watcher).
- **v0.4:** Monitor de Conexões de Rede (Sockets & DNS).
- **v0.5:** Motor de Regras de Detecção & Sistema de Alertas.
- **v1.0:** Agente de Resposta Automática & Isolação de Endpoint Estável.
