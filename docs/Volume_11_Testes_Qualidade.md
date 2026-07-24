# GUARDIAN EDR PLATFORM 🛡️
## Volume 11 — Estratégia de Testes, Qualidade & Homologação
**Versão:** 1.0.0  
**Ferramentas:** Cargo Test, Jest/Vitest, k6, Atomic Red Team  
**Status:** Especificação Técnica de Engenharia  

---

## 📑 Sumário

1. [Capítulo 1 — Pirâmide de Testes de Software](#capítulo-1--pirâmide-de-testes-de-software)
2. [Capítulo 2 — Testes de Carga & Estresse (High Throughput)](#capítulo-2--testes-de-carga--estresse-high-throughput)
3. [Capítulo 3 — Simulação de Ameaças & Red Teaming (Atomic Red Team)](#capítulo-3--simulação-de-ameaças--red-teaming-atomic-red-team)

---

## Capítulo 1 — Pirâmide de Testes de Software

```text
                     ▲
                    / \
                   /E2E\             (Cenas completas de ataque + Dashboard)
                  /-----\
                 / Integ \           (Agente Rust <-> API Core Server)
                /---------\
               / Unitários \         (Regras, Parsers, Hashing, Tokio Channels)
              └─────────────┘
```

1. **Testes Unitários no Agente Rust:** Executados via `cargo test`. Garantem o funcionamento correto do cálculo de SHA-256 e da serialização de telemetrias.
2. **Testes de Integração na API Core:** Executados via `npm test` / `vitest`. Validam a resposta dos endpoints REST `/agents/register`, `/agents/heartbeat` e `/events`.
3. **Testes E2E (End-to-End):** Validam a transmissão de telemetrias em tempo real do agente até a renderização dos componentes no `Guardian Console`.

---

## Capítulo 2 — Testes de Carga & Estresse (High Throughput)

Para homologar a capacidade do servidor `Guardian Core` em suportar redes corporativas de grande porte:
- **Ferramenta:** Scripts `k6` simulando **10.000 agentes simultâneos**.
- **Cenário de Teste:** Cada agente simulado envia 1 heartbeat a cada 30s e 5 eventos de processo/rede por segundo.
- **Métricas Aceitáveis de Qualidade:**
  - Taxa de Sucesso de Requisições: $> 99.99\%$ (`HTTP 200/201`).
  - Latência P95: $< 25\text{ms}$.
  - Latência P99: $< 50\text{ms}$.

---

## Capítulo 3 — Simulação de Ameaças & Red Teaming (Atomic Red Team)

Antes de promover uma nova versão para produção, o sistema é testado contra scripts do **Atomic Red Team**:
- **Teste T1059.001 (PowerShell):** Executa `powershell.exe -e JABz...` e verifica se o alerta `RULE-WIN-001` é disparado no painel em menos de 2 segundos.
- **Teste T1486 (Ransomware):** Cria 500 arquivos temporários de teste e os renomeia rapidamente para verificar o disparo da regra `RULE-FILE-002`.
