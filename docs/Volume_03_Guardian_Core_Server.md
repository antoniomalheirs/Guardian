# GUARDIAN EDR PLATFORM 🛡️
## Volume 3 — Guardian Core (Server API) — Especificação Técnica Detalhada
**Versão:** 1.0.0  
**Tecnologia:** Go / Node.js (TypeScript Server)  
**Status:** Especificação Técnica de Engenharia  

---

## 📑 Sumário

1. [Capítulo 1 — Visão Geral do Guardian Core](#capítulo-1--visão-geral-do-guardian-core)
2. [Capítulo 2 — Arquitetura da API & Middlewares](#capítulo-2--arquitetura-da-api--middlewares)
3. [Capítulo 3 — Especificação OpenAPI 3.0 dos Endpoints](#capítulo-3--especificação-openapi-30-dos-endpoints)
4. [Capítulo 4 — Camada de Ingestão e Cache de Alta Velocidade](#capítulo-4--camada-de-ingestão-e-cache-de-alta-velocidade)
5. [Capítulo 5 — Escalabilidade e Alta Disponibilidade](#capítulo-5--escalabilidade-e-alta-disponibilidade)

---

## Capítulo 1 — Visão Geral do Guardian Core

O **Guardian Core** é o cérebro central da plataforma EDR. Suas responsabilidades primárias são:
1. **Autenticar e Registrar Agentes:** Atribuir IDs únicos e guardar a configuração de inventário de cada endpoint.
2. **Processar Batimentos Cardíacos (Heartbeats):** Monitorar o status de vida dos agentes (Online, Warning, Offline) a cada 30 segundos.
3. **Ingestão Telemétrica de Alta Throughput:** Receber lotes de eventos telemétricos (Processos, Arquivos, Redes), descompactar, validar e encaminhar para a persistência e para o motor de regras.
4. **Alimentar o Dashboard (Guardian Console):** Fornecer respostas rápidas de consulta REST/WebSocket para o painel de administradores de segurança.

---

## Capítulo 2 — Arquitetura da API & Middlewares

```text
 ┌──────────────────────────────────────────────────────────┐
 │                     Requisição HTTP                      │
 └──────────────────────────┬───────────────────────────────┘
                            │
                            ▼
 ┌──────────────────────────────────────────────────────────┐
 │                Middleware 1: CORS & Headers              │
 └──────────────────────────┬───────────────────────────────┘
                            │
                            ▼
 ┌──────────────────────────────────────────────────────────┐
 │            Middleware 2: Rate Limiting & Auth            │
 └──────────────────────────┬───────────────────────────────┘
                            │
                            ▼
 ┌──────────────────────────────────────────────────────────┐
 │           Middleware 3: Body Parser & Decompress         │
 └──────────────────────────┬───────────────────────────────┘
                            │
                            ▼
 ┌──────────────────────────────────────────────────────────┐
 │                   Router / Controllers                   │
 ├─────────────────┬───────────────────┬────────────────────┤
 │ AgentController │ HeartbeatControl  │ EventsController   │
 └─────────────────┴───────────────────┴────────────────────┘
```

---

## Capítulo 3 — Especificação OpenAPI 3.0 dos Endpoints

### 3.1 Tabela Resumo dos Endpoints

| Método | Caminho | Descrição |
| :--- | :--- | :--- |
| `GET` | `/api/v1/health` | Healthcheck do servidor API |
| `GET` | `/api/v1/stats` | Estatísticas gerais de contagem de endpoints e eventos |
| `GET` | `/api/v1/agents` | Retorna a lista completa de endpoints cadastrados |
| `GET` | `/api/v1/agents/:id` | Detalhes e inventário de um endpoint específico |
| `POST` | `/api/v1/agents/register` | Registro inicial do agente no servidor |
| `POST` | `/api/v1/agents/heartbeat` | Ingestão do batimento e telemetria de uso de recursos |
| `GET` | `/api/v1/events` | Histórico dos últimos eventos telemétricos capturados |
| `POST` | `/api/v1/events` | Ingestão de novos eventos telemétricos capturados pelo agente |

---

## Capítulo 4 — Camada de Ingestão e Cache de Alta Velocidade

### 4.1 Estratégia de Cache para Status de Agentes (Redis)
Para evitar chamadas contínuas ao banco de dados relacional durante os batimentos a cada 30s de milhares de computadores:

- **Chave no Redis:** `agent:status:<agent_id>`
- **Valor armazenado:** Objeto JSON com métricas de CPU/RAM/Disco e timestamp.
- **TTL (Time to Live):** 90 segundos. Se um agente não enviar heartbeat dentro de 90 segundos, a chave expira e o status do agente no dashboard transita automaticamente para `offline`.

### 4.2 Persistência de Eventos no PostgreSQL
Eventos recebidos são agrupados e inseridos em lotes na tabela `telemetry_events` para garantir que o banco suporte rajadas de milhares de conexões de rede e criações de processos por segundo.

---

## Capítulo 5 — Escalabilidade e Alta Disponibilidade

O `Guardian Core` é projetado como uma aplicação **Stateless (Sem Estado Local)**:
- Múltiplas instâncias do `Guardian Core` podem rodar atrás de um Load Balancer (ex.: NGINX / HAProxy).
- Se uma instância falhar, os agentes redirecionam automaticamente as chamadas HTTP para outra instância disponível sem perda de sessão.
