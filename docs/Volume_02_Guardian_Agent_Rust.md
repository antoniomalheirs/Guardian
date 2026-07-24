# GUARDIAN EDR PLATFORM 🛡️
## Volume 2 — Guardian Agent (Rust) — Especificação Técnica Detalhada
**Versão:** 1.0.0  
**Linguagem:** Rust (Edition 2021)  
**Status:** Especificação Técnica de Engenharia  

---

## 📑 Sumário

1. [Capítulo 1 — Ciclo de Vida e Inicialização do Agente](#capítulo-1--ciclo-de-vida-e-inicialização-do-agente)
2. [Capítulo 2 — Barramento Interno de Eventos (Internal Event Bus)](#capítulo-2--barramento-interno-de-eventos-internal-event-bus)
3. [Capítulo 3 — Especificação Detalhada dos Monitores](#capítulo-3--especificação-detalhada-dos-monitores)
   - [3.1 Process Monitor (Monitor de Processos)](#31-process-monitor-monitor-de-processos)
   - [3.2 File Monitor (Monitor de Arquivos)](#32-file-monitor-monitor-de-arquivos)
   - [3.3 Network Monitor (Monitor de Rede)](#33-network-monitor-monitor-de-rede)
   - [3.4 Registry & Service Monitor](#34-registry--service-monitor)
4. [Capítulo 4 — Fila Circular Local, Lotes e Dispatcher](#capítulo-4--fila-circular-local-lotes-e-dispatcher)
5. [Capítulo 5 — Mecanismo de Atualização Segura (Updater)](#capítulo-5--mecanismo-de-atualização-segura-updater)

---

## Capítulo 1 — Ciclo de Vida e Inicialização do Agente

### 1.1 Fluxo de Boot
O **Guardian Agent** é executado como um serviço do sistema operacional (`Windows Service` / `systemd daemon`). Durante a inicialização, ele executa a seguinte sequência ordenada:

```text
  ┌────────────────────────────────────────────────────────┐
  │                   1. Carregar Config                    │
  │                     (config.toml)                      │
  └──────────────────────────┬─────────────────────────────┘
                             │
                             ▼
  ┌────────────────────────────────────────────────────────┐
  │              2. Inicializar Logger Tracing             │
  └──────────────────────────┬─────────────────────────────┘
                             │
                             ▼
  ┌────────────────────────────────────────────────────────┐
  │             3. Validar Certificado TLS & MAC           │
  └──────────────────────────┬─────────────────────────────┘
                             │
                             ▼
  ┌────────────────────────────────────────────────────────┐
  │           4. Coletar Inventário Inicial do SO          │
  └──────────────────────────┬─────────────────────────────┘
                             │
                             ▼
  ┌────────────────────────────────────────────────────────┐
  │         5. Iniciar Tokio Runtime & Event Bus           │
  └──────────────────────────┬─────────────────────────────┘
                             │
                             ▼
  ┌────────────────────────────────────────────────────────┐
  │       6. Spawnar Tasks de Monitores Independentes      │
  └────────────────────────────────────────────────────────┘
```

---

## Capítulo 2 — Barramento Interno de Eventos (Internal Event Bus)

Para evitar acoplamento direto entre os monitores e o módulo de transmissão de rede, todos os dados coletados são encapsulados em tipos Fortemente Tipados (`Enum Rust`) e postados em canais assíncronos de alta performance (`tokio::sync::mpsc::channel`).

```rust
pub enum AgentEvent {
    ProcessCreated(ProcessTelemetry),
    ProcessExited(ProcessExitTelemetry),
    FileModified(FileTelemetry),
    NetworkConnected(NetworkTelemetry),
    ServiceChanged(ServiceTelemetry),
    RegistryModified(RegistryTelemetry),
    Heartbeat(HeartbeatTelemetry),
}
```

---

## Capítulo 3 — Especificação Detalhada dos Monitores

### 3.1 Process Monitor (Monitor de Processos)

O monitor de processos intercepta a criação e encerramento de executáveis no endpoint.
- **Técnica no Windows:** Assinatura de `ETW (Event Tracing for Windows)` no provider `Microsoft-Windows-Kernel-Process` combinado com chamadas `sysinfo` / `Toolhelp32Snapshot`.
- **Estrutura de Telemetria:**

```rust
pub struct ProcessTelemetry {
    pub pid: u32,
    pub parent_pid: u32,
    pub executable_path: String,
    pub command_line: String,
    pub sha256_hash: String,
    pub user_sid: String,
    pub is_digitally_signed: bool,
    pub timestamp: String,
}
```

### 3.2 File Monitor (Monitor de Arquivos)

Monitora alterações em tempo real no sistema de arquivos.
- **Técnica no Windows:** Utiliza a API `ReadDirectoryChangesW` por meio do crate `notify` em threads assíncronas dedicadas.
- **Diretórios de Alta Prioridade:**
  - `C:\Windows\System32\`
  - `C:\Program Files\`
  - `C:\Users\*\AppData\Roaming\`

```rust
pub struct FileTelemetry {
    pub file_path: String,
    pub action: FileAction, // Created, Modified, Deleted, Renamed
    pub old_path: Option<String>,
    pub file_size_bytes: u64,
    pub sha256_hash: Option<String>,
    pub process_pid: Option<u32>,
}
```

### 3.3 Network Monitor (Monitor de Rede)

Coleta mapeamento ativo de sockets e conexões estabelecidas.
- **Técnica no Windows:** Chamadas `GetExtendedTcpTable` e `GetExtendedUdpTable` para correlacionar porta local, porta remota e IP remoto ao **PID** do processo que abriu o socket.

```rust
pub struct NetworkTelemetry {
    pub pid: u32,
    pub process_name: String,
    pub protocol: String, // TCP / UDP
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}
```

---

## Capítulo 4 — Fila Circular Local, Lotes e Dispatcher

Para garantir resiliência contra instabilidades da rede corporativa ou da internet:

1. **Batching:** O `Dispatcher` acumula até 100 eventos ou aguarda $500\text{ms}$ antes de montar um lote comprimido (`zstd`).
2. **Buffer Local em Disco:** Se o servidor `Guardian Core` não responder no endpoint `POST /api/v1/events`, o lote é automaticamente gravado num arquivo criptografado de buffer circular local (capacidade máxima de $500\text{ MB}$).
3. **Re-envio Automático:** Assim que o Heartbeat for re-estabelecido com sucesso, a fila local descarrega progressivamente os lotes acumulados sem impactar o envio de novos eventos.

---

## Capítulo 5 — Mecanismo de Atualização Segura (Updater)

Para atualizar o binário do agente sem intervenção manual do usuário:

```text
Servidor API Core ──(Notificação de Nova Versão)──► Guardian Agent
                                                          │
                                                          ▼
                                            Download do Binário (.tmp)
                                                          │
                                                          ▼
                                            Verificar Assinatura Ed25519
                                                          │
                                                          ▼
                                            Substituição Atômica (.exe)
                                                          │
                                                          ▼
                                            Reiniciar Serviço do Agente
```
