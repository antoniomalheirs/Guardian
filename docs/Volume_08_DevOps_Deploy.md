# GUARDIAN EDR PLATFORM 🛡️
## Volume 8 — DevOps, CI/CD, Containerização & Deploy
**Versão:** 1.0.0  
**Tecnologia:** Docker, GitHub Actions, WiX Toolset / MSI  
**Status:** Especificação Técnica de Engenharia  

---

## 📑 Sumário

1. [Capítulo 1 — Containerização com Docker & Docker Compose](#capítulo-1--containerização-com-docker--docker-compose)
2. [Capítulo 2 — Pipeline de CI/CD & Cross-Compilation](#capítulo-2--pipeline-de-cicd--cross-compilation)
3. [Capítulo 3 — Empacotamento e Instalação do Agente (MSI / Windows Service)](#capítulo-3--empacotamento-e-instalação-do-agente-msi--windows-service)

---

## Capítulo 1 — Containerização com Docker & Docker Compose

A infraestrutura do servidor central (`Guardian Core`, `Guardian Console`, `PostgreSQL` e `Redis`) é empacotada usando Docker Compose para implantação em 1-comando:

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: guardian_edr
      POSTGRES_USER: guardian_admin
      POSTGRES_PASSWORD: ${DB_PASSWORD}
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  guardian-core:
    build: ./guardian-core
    ports:
      - "4000:4000"
    environment:
      PORT: 4000
      DATABASE_URL: postgres://guardian_admin:${DB_PASSWORD}@postgres:5432/guardian_edr
      REDIS_URL: redis://redis:6379
    depends_on:
      - postgres
      - redis

  guardian-console:
    build: ./guardian-console
    ports:
      - "4001:4001"
    depends_on:
      - guardian-core

volumes:
  pgdata:
```

---

## Capítulo 2 — Pipeline de CI/CD & Cross-Compilation

O pipeline de integração contínua (GitHub Actions) realiza a compilação cruzada do binário do **Guardian Agent** para múltiplas plataformas:

```text
Commit Git ──► Trigger GitHub Actions
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
   x86_64 Win  x86_64 Linux  aarch64 macOS
    (.exe)        (.so)        (.dylib)
```

---

## Capítulo 3 — Empacotamento e Instalação do Agente (MSI / Windows Service)

No Windows, o binário compilado em Rust é empacotado em um arquivo de instalação `.msi`:
- **Privilégios:** Executado com `NT AUTHORITY\SYSTEM`.
- **Registro do Serviço:** Cria a entrada no Services MMC (`sc create GuardianAgentService binPath= ...`).
- **Autostart:** Configurado como `Automatic (Delayed Start)` para garantir que todos os drivers do sistema operacional já estejam inicializados.
