# GUARDIAN EDR PLATFORM 🛡️
## Volume 9 — Modelo de Segurança, Autenticação & mTLS
**Versão:** 1.0.0  
**Padrão de Segurança:** mTLS (Mutual TLS X.509) & RBAC  
**Status:** Especificação Técnica de Engenharia  

---

## 📑 Sumário

1. [Capítulo 1 — Autenticação mTLS Agente <-> Servidor](#capítulo-1--autenticação-mtls-agente---servidor)
2. [Capítulo 2 — Criptografia de Dados (Trânsito e Repouso)](#capítulo-2--criptografia-de-dados-trânsito-e-repouso)
3. [Capítulo 3 — Controle de Acesso Baseado em Funções (RBAC)](#capítulo-3--controle-de-acesso-baseado-em-funções-rbac)
4. [Capítulo 4 — Mecanismos de Anti-Tampering (Autoproteção)](#capítulo-4--mecanismos-de-anti-tampering-autoproteção)

---

## Capítulo 1 — Autenticação mTLS Agente <-> Servidor

Para garantir que apenas endpoints legítimos consigam se registrar e enviar dados ao servidor `Guardian Core`:

```text
Guardian Agent (Rust) ◄────── (Handshake TLS 1.3 mTLS) ──────► Guardian Core Server
 (Apresenta Certificado                                         (Valida Certificado
   Cliente X.509)                                                contra CA Interna)
```

1. **Autoridade Certificadora Interna (Guardian Internal CA):** Durante o provisionamento do agente no computador, um certificado de cliente X.509 exclusivo é gerado e assinado pela CA do servidor.
2. **Validação Rigorosa:** Se um hacker tentar simular um agente sem o certificado válido assinado pela CA, a conexão TCP é abortada instantaneamente no nível TLS.

---

## Capítulo 2 — Criptografia de Dados (Trânsito e Repouso)

- **Em Trânsito:** Todo o tráfego utiliza obrigatoriamente **TLS 1.3** com cipher suites de alta segurança (`TLS_AES_256_GCM_SHA384` / `TLS_CHACHA20_POLY1305_SHA256`).
- **Em Repouso:** Credenciais, tokens de API e arquivos mantidos em quarentena utilizam encriptação simétrica **AES-256-GCM**.

---

## Capítulo 3 — Controle de Acesso Baseado em Funções (RBAC)

O `Guardian Console` divide as permissões dos administradores em três perfis:

| Papel (Role) | Permissões |
| :--- | :--- |
| `SOC_ANALYST` | Visualização total de eventos/alertas + execução de ações de mitigação (*Isolar Host*, *Kill PID*). |
| `SECURITY_AUDITOR` | Leitura total de relatórios, inventários e logs para fins de auditoria (Sem permissão de isolar hosts). |
| `SYSTEM_ADMIN` | Gerenciamento total da plataforma, adição de novos usuários, edição de regras e configurações do servidor. |

---

## Capítulo 4 — Mecanismos de Anti-Tampering (Autoproteção)

Para evitar que um malware tente finalizar o serviço do `Guardian Agent`:
1. **DACLs Estritas no Windows Service:** O serviço é registrado com permissão restrita, impedindo que usuários sem privilégios `SYSTEM` executem `taskkill` ou `net stop`.
2. **Verificação Diária de Integridade:** O binário verifica continuamente a sua própria assinatura digital Authenticode e hash SHA-256 antes de executar qualquer rotina crítica.
