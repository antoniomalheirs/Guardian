# GUARDIAN EDR PLATFORM 🛡️
## Volume 6 — Rules Engine & Ciência de Detecção
**Versão:** 1.0.0  
**Alinhamento:** MITRE ATT&CK® Framework  
**Status:** Especificação Técnica de Engenharia  

---

## 📑 Sumário

1. [Capítulo 1 — Filosofia da Ciência de Detecção](#capítulo-1--filosofia-da-ciência-de-detecção)
2. [Capítulo 2 — Linguagem Declarativa de Regras (DSL)](#capítulo-2--linguagem-declarativa-de-regras-dsl)
3. [Capítulo 3 — Catálogo de Regras de Detecção de Ameaças](#capítulo-3--catálogo-de-regras-de-detecção-de-ameaças)
4. [Capítulo 4 — Algoritmo de Avaliação In-Memory](#capítulo-4--algoritmo-de-avaliação-in-memory)

---

## Capítulo 1 — Filosofia da Ciência de Detecção

O **Guardian Rules Engine** avalia continuamente a telemetria enviada pelos agentes contra um catálogo de regras alinhadas à matriz **MITRE ATT&CK®**.

```text
 ┌──────────────────────────────────────────────────────────┐
 │               Mapeamento MITRE ATT&CK®                   │
 ├───────────────────┬───────────────────┬──────────────────┤
 │ Execution (T1059) │ Defense Evasion   │ Credential Access│
 │ PowerShell Encoded│ Registry Hiding   │ LSASS Dump T1003 │
 └───────────────────┴───────────────────┴──────────────────┘
```

---

## Capítulo 2 — Linguagem Declarativa de Regras (DSL)

As regras são especificadas em JSON/YAML e contêm operadores lógicos para correspondência de padrões:

```json
{
  "ruleId": "RULE-WIN-001",
  "name": "PowerShell Encoded Command Execution",
  "mitreTechnique": "T1059.001",
  "severity": "HIGH",
  "category": "PROCESS",
  "conditions": [
    {
      "field": "processName",
      "operator": "EQUALS",
      "value": "powershell.exe"
    },
    {
      "field": "commandLine",
      "operator": "CONTAINS_ANY",
      "values": ["-EncodedCommand", "-enc", "-e "]
    }
  ],
  "action": "GENERATE_ALERT"
}
```

---

## Capítulo 3 — Catálogo de Regras de Detecção de Ameaças

### 3.1 Tabela de Regras Padrão (v1.0)

| ID da Regra | Nome | Severidade | Técnica MITRE | Descrição |
| :--- | :--- | :--- | :--- | :--- |
| `RULE-WIN-001` | PowerShell Encoded Command | `HIGH` | T1059.001 | Execução de comandos codificados em Base64 para ocultar script. |
| `RULE-FILE-002` | Ransomware File Spike | `CRITICAL` | T1486 | Modificação em massa rápida de arquivos em diretórios do usuário. |
| `RULE-NET-003` | C2 Reverse Shell Connection | `HIGH` | T1071 | Conexão de saída para portas não padronizadas (ex: 4444, 6667). |
| `RULE-MEM-004` | LSASS Process Dump | `CRITICAL` | T1003.001 | Leitura/dumping da memória do processo `lsass.exe` para roubo de credenciais. |
| `RULE-REG-005` | Registry Persistence Run Key | `WARNING` | T1547.001 | Adição de executáveis em chaves de auto-inicialização no Registro. |

---

## Capítulo 4 — Algoritmo de Avaliação In-Memory

Para processar milhares de eventos por segundo sem degradar o servidor:
1. **Triagem de Categoria:** O evento é encaminhado apenas para o subconjunto de regras daquela categoria (`PROCESS`, `FILE` ou `NETWORK`).
2. **Avaliação Sem Bloqueio:** As regras são avaliadas em threads assíncronas paralelas.
3. **Deduplicação de Alertas:** Se a mesma regra for disparada no mesmo endpoint em um intervalo $< 60\text{s}$, os alertas são agrupados para evitar *alert fatigue* no painel do analista.
