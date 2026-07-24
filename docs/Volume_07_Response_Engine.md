# GUARDIAN EDR PLATFORM 🛡️
## Volume 7 — Response Engine & Mitigação Automática de Ameaças
**Versão:** 1.0.0  
**Escopo:** Mitigação Automatizada e Resposta Remota  
**Status:** Especificação Técnica de Engenharia  

---

## 📑 Sumário

1. [Capítulo 1 — Filosofia do Framework de Resposta](#capítulo-1--filosofia-do-framework-de-resposta)
2. [Capítulo 2 — Mecanismo de Isolação de Rede (Host Isolation)](#capítulo-2--mecanismo-de-isolação-de-rede-host-isolation)
3. [Capítulo 3 — Sistema de Quarentena Criptografada de Arquivos](#capítulo-3--sistema-de-quarentena-criptografada-de-arquivos)
4. [Capítulo 4 — Trilha de Auditoria & Reversão de Ações (Rollback)](#capítulo-4--trilha-de-auditoria--reversão-de-ações-rollback)

---

## Capítulo 1 — Filosofia do Framework de Resposta

O **Guardian Response Engine** executa ações de mitigação atômicas para conter a propagação de invasões e malwares nos endpoints.

```text
               Severidade do Alerta ──► Matriz de Resposta
                                            │
         ┌──────────────────────────────────┼──────────────────────────────────┐
         ▼                                  ▼                                  ▼
 Level 2: Kill PID                Level 3: Quarentena                Level 4: Isolação de Host
(Finalizar Processo)            (AES-256 no Arquivo)                (Firewall Bloqueia Rede)
```

---

## Capítulo 2 — Mecanismo de Isolação de Rede (Host Isolation)

Quando um host é isolado (seja por automação de regra `CRITICAL` ou por clique do analista no painel):
1. O servidor `Guardian Core` despacha a ordem de isolamento.
2. O `Guardian Agent` (Rust) aciona a API de firewall nativa do SO (`Windows Filtering Platform - WFP` / `netsh`).
3. É criada uma regra de negação total de tráfego de entrada e saída, **mantendo aberta exclusivamente a conexão TLS com a porta do Guardian Core (Porta 4000)** para gerenciamento remoto.

---

## Capítulo 3 — Sistema de Quarentena Criptografada de Arquivos

Se um arquivo malicioso for identificado:
- O agente altera a permissão de acesso (`ACL`), revogando permissão de execução.
- O arquivo é encriptado via **AES-256-GCM**.
- O binário encriptado é movido para o diretório isolado: `C:\ProgramData\Guardian\Quarantine\`.

---

## Capítulo 4 — Trilha de Auditoria & Reversão de Ações (Rollback)

Todas as ações de mitigação geram um registro imutável na tabela `telemetry_events` contendo:
- `Action`: `ISOLATE_HOST` | `KILL_PROCESS` | `QUARANTINE_FILE`.
- `InitiatedBy`: Nome do analista de segurança ou `AUTOMATED_RULE_ENGINE`.
- **Reversão:** O analista pode reativar a rede do host ou restaurar um arquivo de quarentena com 1-clique pelo `Guardian Console`.
