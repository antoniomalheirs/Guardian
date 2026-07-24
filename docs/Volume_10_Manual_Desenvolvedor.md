# GUARDIAN EDR PLATFORM 🛡️
## Volume 10 — Manual do Desenvolvedor & Guia de Contribuição
**Versão:** 1.0.0  
**Público-Alvo:** Engenheiros de Software, Desenvolvedores & Pesquisadores de Segurança  
**Status:** Especificação Técnica de Engenharia  

---

## 📑 Sumário

1. [Capítulo 1 — Configuração do Ambiente de Desenvolvimento](#capítulo-1--configuração-do-ambiente-de-desenvolvimento)
2. [Capítulo 2 — Padrões de Código e Convenções](#capítulo-2--padrões-de-código-e-convenções)
3. [Capítulo 3 — Como Adicionar um Novo Monitor no Agente Rust](#capítulo-3--como-adicionar-um-novo-monitor-no-agente-rust)
4. [Capítulo 4 — Como Criar e Registrar uma Nova Regra de Detecção](#capítulo-4--como-criar-e-registrar-uma-nova-regra-de-detecção)

---

## Capítulo 1 — Configuração do Ambiente de Desenvolvimento

### 1.1 Pré-requisitos
- **Rust Toolchain (v1.75+):** `rustup default stable`
- **Node.js (v20+):** `node -v`
- **Git:** `git --version`

### 1.2 Inicialização Rápida do Monorepositório

```bash
# 1. Clonar o repositório
git clone b:\Git\Guardian
cd Guardian

# 2. Instalar dependências da API Core Server (Porta 4000)
cd guardian-core
npm install
npm run build
node dist/index.js &

# 3. Instalar dependências da Dashboard Web (Porta 4001)
cd ../guardian-console
npm install
npm run dev &

# 4. Compilar e executar o Agente Rust
cd ../guardian-agent
cargo run
```

---

## Capítulo 2 — Padrões de Código e Convenções

- **Rust:** Todo o código do `guardian-agent` deve obrigatoriamente passar na verificação do `cargo clippy -- -D warnings` e ser formatado via `cargo fmt`.
- **TypeScript:** O `guardian-core` e o `guardian-console` utilizam modo estrito (`"strict": true` no `tsconfig.json`). Evitar o uso do tipo `any` sem justificativa.

---

## Capítulo 3 — Como Adicionar um Novo Monitor no Agente Rust

Para implementar um novo monitor (ex.: `UsbMonitor`):

1. Crie o arquivo `src/monitors/usb.rs`.
2. Defina a struct e a função assíncrona de captura:
```rust
use crate::event_bus::AgentEvent;
use tokio::sync::mpsc::Sender;

pub async fn run_usb_monitor(tx: Sender<AgentEvent>) {
    loop {
        // Lógica de escuta de inserção de dispositivos USB
        // tx.send(AgentEvent::UsbInserted(...)).await.unwrap();
        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
    }
}
```
3. Registre o spawn da task no `main.rs`:
```rust
tokio::spawn(run_usb_monitor(event_tx.clone()));
```

---

## Capítulo 4 — Como Criar e Registrar uma Nova Regra de Detecção

Para registrar uma nova regra no `guardian-core`:
1. Abra `guardian-core/src/index.ts`.
2. Adicione a especificação do objeto no array `activeRules`:
```typescript
{
  ruleId: 'RULE-USB-005',
  name: 'Unauthorized Mass Storage USB Device',
  category: 'SECURITY',
  severity: 'WARNING',
  description: 'Detecta a conexão de pendrives não autorizados na máquina',
  enabled: true
}
```
