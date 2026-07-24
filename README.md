# Guardian EDR Platform 🛡️

O **Guardian EDR** é uma plataforma modular de *Endpoint Detection and Response* (EDR) projetada para alta performance, observabilidade de ativos, detecção de ameaças e resposta automatizada a incidentes em sistemas operacionais.

---

## 🏗️ Arquitetura do Monorepositório

```text
Guardian/
├── guardian-agent/        # Agente de Endpoint em Rust (telemetria, monitores, event bus)
├── guardian-core/         # Servidor Central API em Go / Node (ingestão de telemetria, regras, persistência)
├── guardian-console/      # Painel Dashboard Web em React + TypeScript + Vite (interface em tempo real)
└── docs/                  # Documentação Técnica Oficial (Coleção Completa de 12 Volumes)
    ├── Volume_01_Arquitetura_Geral.md        # Visão Geral, Requisitos e Modelo C4
    ├── Volume_02_Guardian_Agent_Rust.md       # Especificação Interna do Agente Rust & Monitores
    ├── Volume_03_Guardian_Core_Server.md      # Especificação do Servidor API & Endpoints OpenAPI 3.0
    ├── Volume_04_Guardian_Console.md          # Especificação do Dashboard Web & UX
    ├── Volume_05_Guardian_Database.md         # Modelagem do Banco de Dados PostgreSQL & Redis
    ├── Volume_06_Rules_Engine.md              # Motor de Regras de Detecção & MATRIZ MITRE ATT&CK
    ├── Volume_07_Response_Engine.md           # Resposta Automatizada, Quarentena & Isolação
    ├── Volume_08_DevOps_Deploy.md             # Docker, CI/CD, Cross-Compilation & Instalador MSI
    ├── Volume_09_Seguranca_Autenticacao.md    # Autenticação mTLS X.509, RBAC & Anti-Tampering
    ├── Volume_10_Manual_Desenvolvedor.md     # Guia do Desenvolvedor & Criação de Monitores/Regras
    ├── Volume_11_Testes_Qualidade.md          # Pirâmide de Testes, Carga k6 & Atomic Red Team
    └── Volume_12_Manual_Administrador.md      # Manual Operacional do SOC & Playbooks de Resposta
```

---

## 🚀 Módulos

### 1. Guardian Agent (Rust)
Instalado em cada endpoint para monitorar o SO.
- **Metas de Desempenho:** RAM < 60 MB, CPU < 1%, Heartbeat a cada 30s.
- **Recursos:** Inventário de Hardware/SO, Monitor de Processos, Hashes SHA-256, Conexões de Rede TCP/UDP e Barramento de Eventos assíncrono Tokio.

### 2. Guardian Core (Server API - Porta 4000)
Servidor central de alta velocidade.
- Autenticação e Registro de Agentes (`POST /api/v1/agents/register`).
- Ingestão de Telemetria e Heartbeat (`POST /api/v1/agents/heartbeat`).
- Endpoints de Processos (`/processes`), Conexões de Rede (`/network`), Regras (`/rules`) e Alertas (`/alerts`).
- Endpoints de Resposta a Incidentes (`/response/isolate`, `/response/kill`).

### 3. Guardian Console (React + Vite - Porta 4001)
Interface Web responsiva para administradores de segurança.
- Status em tempo real dos endpoints (Online / Offline / Warning / Isolated).
- Métricas ao vivo de CPU, RAM e Disco por máquina.
- Inspector de Processos com SHA-256 e Inspector de Sockets de Rede.
- Painel de Regras & Alertas com Ações de Resposta a Incidentes em 1-Clique.

---

## 📋 Pré-requisitos de Desenvolvimento
- **Rust / Cargo** (compilando `guardian-agent`)
- **Node.js v24 & npm** (rodando `guardian-core` e `guardian-console`)

---

## 💻 Licença
Desenvolvido como projeto de engenharia de segurança de sistemas.
