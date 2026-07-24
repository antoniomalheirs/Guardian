# GUARDIAN EDR PLATFORM 🛡️
## Volume 4 — Guardian Console (Web Dashboard) — Especificação de Interface & UX
**Versão:** 1.0.0  
**Tecnologia:** React + TypeScript + Vite  
**Status:** Especificação Técnica de Engenharia  

---

## 📑 Sumário

1. [Capítulo 1 — UX & Filosofia de Design System](#capítulo-1--ux--filosofia-de-design-system)
2. [Capítulo 2 — Arquitetura de Componentes & Gerenciamento de Estado](#capítulo-2--arquitetura-de-componentes--gerenciamento-de-estado)
3. [Capítulo 3 — Atualizações Telemétricas em Tempo Real](#capítulo-3--atualizações-telemétricas-em-tempo-real)
4. [Capítulo 4 — Fluxos de Resposta a Incidentes (1-Click Remediation)](#capítulo-4--fluxos-de-resposta-a-incidentes-1-click-remediation)

---

## Capítulo 1 — UX & Filosofia de Design System

O **Guardian Console** é o centro de controle dos analistas de segurança do SOC. Ele foi projetado sob os seguintes princípios de experiência do usuário:
- **Aesthetic First:** Design visual impressionante no estilo *Dark Glassmorphism* (fundo translúcido com desfoque de 16px), paleta de cores tailormade em HSL (Cyan `#06b6d4`, Blue `#3b82f6`, Emerald `#10b981`, Amber `#f59e0b`, Crimson `#f43f5e`).
- **Navegação Intuitiva:** Tabs rápidas para alternar entre Endpoints, Processos, Conexões de Rede, Regras/Alertas e Eventos.
- **Feedback Visual Imediato:** Badges animados (`pulse-ring`) indicando computadores em estado `online`, `warning` ou `isolated`.

---

## Capítulo 2 — Arquitetura de Componentes & Gerenciamento de Estado

```text
                                App (Componente Raiz)
                                          │
            ┌─────────────────────────────┼─────────────────────────────┐
            ▼                             ▼                             ▼
   Header & Tabs Bar              Metrics Overview Panel          Main Content Router
(Endpoints, Processes,             (Total Agents, Active          ┌───────────────────┐
 Network, Rules, Events)          Sockets, Alerts, Procs)         │  - Endpoints Grid │
                                                                  │  - Process Table  │
                                                                  │  - Network Table  │
                                                                  │  - Alerts Panel   │
                                                                  │  - Event Timeline │
                                                                  └───────────────────┘
```

---

## Capítulo 3 — Atualizações Telemétricas em Tempo Real

1. **Polling Adaptativo:** O painel efetua chamadas assíncronas a cada 10 segundos para `/api/v1/agents`, `/api/v1/processes`, `/api/v1/network`, `/api/v1/alerts` e `/api/v1/events`.
2. **Resiliência a Desconexões:** Caso o servidor Core seja reiniciado, o console mantém o último estado válido em cache e exibe um indicador suave de reconexão sem travar a interface do usuário.

---

## Capítulo 4 — Fluxos de Resposta a Incidentes (1-Click Remediation)

Os analistas de segurança possuem controles diretos na interface para mitigação de ameaças:

```text
Analista clica em "Isolar Host" ──► POST /api/v1/response/isolate ──► Servidor altera estado para 'isolated'
                                                                               │
                                                                               ▼
                                                                  Notificação na UI + Host Bloqueado
```

- **Isolamento de Host:** Altera o status do agente no servidor para `isolated`, disparando o bloqueio de rede no endpoint.
- **Encerramento Remoto de Processo:** Envia a chamada `POST /api/v1/response/kill` passando a tupla `(agentId, pid)` para finalizar o executável malicioso instantaneamente.
