use std::env;
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::net::UdpSocket;
use std::time::Duration;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sysinfo::System;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemInventory {
    pub hostname: String,
    pub os_name: String,
    pub os_version: String,
    pub architecture: String,
    pub cpu_model: String,
    pub total_memory_mb: u64,
    pub ip_address: String,
    pub mac_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessTelemetry {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub name: String,
    pub executable_path: String,
    pub command_line: String,
    pub cpu_pct: f32,
    pub memory_mb: u64,
    pub sha256_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkTelemetry {
    pub pid: u32,
    pub process_name: String,
    pub protocol: String,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileTelemetry {
    pub file_path: String,
    pub action: String,
    pub file_size_bytes: u64,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityFinding {
    pub finding_type: String,
    pub severity: String,
    pub description: String,
    pub evidence: String,
    pub mitre_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TelemetryPayload {
    pub agent_id: String,
    pub timestamp: String,
    pub cpu_usage_pct: f32,
    pub memory_usage_pct: f32,
    pub disk_usage_pct: f32,
    pub active_processes_count: usize,
    pub events_count: usize,
    pub top_processes: Vec<ProcessTelemetry>,
    pub network_connections: Vec<NetworkTelemetry>,
    pub file_events: Vec<FileTelemetry>,
    pub security_findings: Vec<SecurityFinding>,
}

fn get_primary_ip_address() -> String {
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|socket| {
            socket.connect("8.8.8.8:80")?;
            socket.local_addr()
        })
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|_| "127.0.0.1".to_string())
}

fn compute_sha256(path_str: &str) -> String {
    let path = Path::new(path_str);
    if !path.is_file() {
        return "UNKNOWN/SYSTEM".to_string();
    }
    match File::open(path) {
        Ok(mut file) => {
            let mut hasher = Sha256::new();
            let mut buffer = [0u8; 8192];
            let mut bytes_read = 0;
            while let Ok(count) = file.read(&mut buffer) {
                if count == 0 || bytes_read > 1_048_576 {
                    break;
                }
                hasher.update(&buffer[..count]);
                bytes_read += count;
            }
            hex::encode(hasher.finalize())
        }
        Err(_) => "ACCESS_DENIED".to_string(),
    }
}

/// Get real MAC address via `getmac` on Windows or reading /sys/class/net on Linux
fn get_real_mac_address() -> String {
    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("getmac")
            .args(&["/fo", "csv", "/nh"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                // Format: "AA-BB-CC-DD-EE-FF","\\Device\\..."
                let parts: Vec<&str> = line.split(',').collect();
                if let Some(mac_raw) = parts.first() {
                    let mac = mac_raw.trim_matches('"').trim();
                    if mac.len() >= 17 && mac != "N/A" {
                        return mac.replace('-', ":").to_uppercase();
                    }
                }
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        for iface in &["wlan0", "eth0", "wlan1", "en0"] {
            let path = format!("/sys/class/net/{}/address", iface);
            if let Ok(mac) = fs::read_to_string(&path) {
                let mac = mac.trim().to_uppercase();
                if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                    return mac;
                }
            }
        }
    }

    "00:00:00:00:00:00".to_string()
}

/// Get real disk usage percentage via WMIC on Windows or statvfs on Linux
fn get_real_disk_usage() -> f32 {
    #[cfg(target_os = "windows")]
    {
        // Use WMIC to get disk usage for C:
        if let Ok(output) = std::process::Command::new("wmic")
            .args(&["logicaldisk", "where", "DeviceID='C:'", "get", "Size,FreeSpace", "/format:csv"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let parts: Vec<&str> = line.split(',').collect();
                // CSV format: Node,FreeSpace,Size
                if parts.len() >= 3 {
                    if let (Ok(free), Ok(total)) = (
                        parts[1].trim().parse::<u64>(),
                        parts[2].trim().parse::<u64>(),
                    ) {
                        if total > 0 {
                            let used = total - free;
                            return (used as f32 / total as f32) * 100.0;
                        }
                    }
                }
            }
        }
        // Fallback: PowerShell
        if let Ok(output) = std::process::Command::new("powershell")
            .args(&["-Command", "(Get-PSDrive C).Used / ((Get-PSDrive C).Used + (Get-PSDrive C).Free) * 100"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Ok(pct) = stdout.trim().parse::<f32>() {
                return pct;
            }
        }
    }
    0.0
}

/// Parse `netstat -ano` output to get REAL network connections with PIDs
fn get_real_network_connections(sys: &System) -> Vec<NetworkTelemetry> {
    let mut connections = Vec::new();

    // Build PID -> process name map from sysinfo
    let mut pid_name_map: HashMap<u32, String> = HashMap::new();
    for (pid, proc_) in sys.processes() {
        pid_name_map.insert(pid.as_u32(), proc_.name().to_string());
    }

    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("netstat")
            .args(&["-ano", "-p", "tcp"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let line = line.trim();
                if line.starts_with("TCP") || line.starts_with("tcp") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 5 {
                        let protocol = parts[0].to_uppercase();
                        let local = parts[1];
                        let remote = parts[2];
                        let status = parts[3].to_uppercase();
                        let pid_str = parts[4];

                        let pid: u32 = pid_str.parse().unwrap_or(0);

                        // Parse local address:port
                        let (local_addr, local_port) = parse_netstat_addr(local);
                        let (remote_addr, remote_port) = parse_netstat_addr(remote);

                        // Skip loopback-to-loopback
                        if local_addr == "127.0.0.1" && remote_addr == "127.0.0.1" {
                            continue;
                        }

                        let proc_name = pid_name_map
                            .get(&pid)
                            .cloned()
                            .unwrap_or_else(|| format!("pid-{}", pid));

                        connections.push(NetworkTelemetry {
                            pid,
                            process_name: proc_name,
                            protocol,
                            local_address: local_addr,
                            local_port,
                            remote_address: remote_addr,
                            remote_port,
                            status,
                        });
                    }
                }
            }
        }

        // Also capture UDP sockets
        if let Ok(output) = std::process::Command::new("netstat")
            .args(&["-ano", "-p", "udp"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let line = line.trim();
                if line.starts_with("UDP") || line.starts_with("udp") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 4 {
                        let local = parts[1];
                        let remote = parts[2];
                        let pid_str = parts[3];
                        let pid: u32 = pid_str.parse().unwrap_or(0);

                        let (local_addr, local_port) = parse_netstat_addr(local);
                        let (remote_addr, remote_port) = parse_netstat_addr(remote);

                        let proc_name = pid_name_map
                            .get(&pid)
                            .cloned()
                            .unwrap_or_else(|| format!("pid-{}", pid));

                        connections.push(NetworkTelemetry {
                            pid,
                            process_name: proc_name,
                            protocol: "UDP".to_string(),
                            local_address: local_addr,
                            local_port,
                            remote_address: remote_addr,
                            remote_port,
                            status: "LISTENING".to_string(),
                        });
                    }
                }
            }
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        // On Linux, read /proc/net/tcp
        if let Ok(content) = fs::read_to_string("/proc/net/tcp") {
            for line in content.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 10 {
                    let local = parts[1];
                    let remote = parts[2];
                    let state_hex = parts[3];
                    let (local_addr, local_port) = parse_proc_net_addr(local);
                    let (remote_addr, remote_port) = parse_proc_net_addr(remote);
                    let status = match state_hex {
                        "01" => "ESTABLISHED",
                        "02" => "SYN_SENT",
                        "0A" => "LISTEN",
                        "06" => "TIME_WAIT",
                        "08" => "CLOSE_WAIT",
                        _ => "OTHER",
                    };

                    connections.push(NetworkTelemetry {
                        pid: 0,
                        process_name: "linux-sock".to_string(),
                        protocol: "TCP".to_string(),
                        local_address: local_addr,
                        local_port,
                        remote_address: remote_addr,
                        remote_port,
                        status: status.to_string(),
                    });
                }
            }
        }
    }

    // Limit to 50 most interesting connections (ESTABLISHED first)
    connections.sort_by(|a, b| {
        let priority = |s: &str| -> u8 {
            match s {
                "ESTABLISHED" => 0,
                "SYN_SENT" => 1,
                "TIME_WAIT" => 2,
                "LISTENING" | "LISTEN" => 3,
                _ => 5,
            }
        };
        priority(&a.status).cmp(&priority(&b.status))
    });
    connections.truncate(50);
    connections
}

/// Parse netstat address format "192.168.50.140:4000" or "[::1]:8080"
fn parse_netstat_addr(addr_str: &str) -> (String, u16) {
    // Handle IPv6 bracket notation [::1]:port
    if addr_str.starts_with('[') {
        if let Some(bracket_end) = addr_str.rfind("]:") {
            let ip = addr_str[1..bracket_end].to_string();
            let port: u16 = addr_str[bracket_end + 2..].parse().unwrap_or(0);
            return (ip, port);
        }
    }
    // Standard IPv4 addr:port
    if let Some(colon_pos) = addr_str.rfind(':') {
        let ip = addr_str[..colon_pos].to_string();
        let port: u16 = addr_str[colon_pos + 1..].parse().unwrap_or(0);
        (ip, port)
    } else {
        (addr_str.to_string(), 0)
    }
}

/// Parse /proc/net/tcp hex IP:PORT format on Linux
#[cfg(not(target_os = "windows"))]
fn parse_proc_net_addr(hex_str: &str) -> (String, u16) {
    if let Some((ip_hex, port_hex)) = hex_str.split_once(':') {
        let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);
        if ip_hex.len() == 8 {
            let ip_int = u32::from_str_radix(ip_hex, 16).unwrap_or(0);
            let bytes = ip_int.to_le_bytes();
            let ip = format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]);
            return (ip, port);
        }
        return (ip_hex.to_string(), port);
    }
    ("0.0.0.0".to_string(), 0)
}

/// Monitor critical system directories for file changes
fn get_real_file_events(file_snapshot: &mut HashMap<String, (u64, u64)>) -> Vec<FileTelemetry> {
    let mut events = Vec::new();

    // Define watched directories per OS
    #[cfg(target_os = "windows")]
    let watch_dirs: Vec<String> = {
        let userprofile = env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Default".to_string());
        vec![
            format!("{}\\Downloads", userprofile),
            format!("{}\\Desktop", userprofile),
            format!("{}\\Documents", userprofile),
            "C:\\Windows\\Temp".to_string(),
        ]
    };

    #[cfg(not(target_os = "windows"))]
    let watch_dirs: Vec<String> = vec![
        "/tmp".to_string(),
        "/home".to_string(),
        "/sdcard/Download".to_string(),
    ];

    let mut current_snapshot: HashMap<String, (u64, u64)> = HashMap::new();

    for dir in &watch_dirs {
        let dir_path = Path::new(dir);
        if !dir_path.is_dir() {
            continue;
        }
        if let Ok(entries) = fs::read_dir(dir_path) {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata() {
                    if meta.is_file() {
                        let path = entry.path().to_string_lossy().to_string();
                        let mtime = meta.modified()
                            .map(|t| t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs())
                            .unwrap_or(0);
                        let size = meta.len();
                        current_snapshot.insert(path, (mtime, size));
                    }
                }
            }
        }
    }

    // Compare with previous snapshot
    if !file_snapshot.is_empty() {
        for (fpath, &(mtime, size)) in &current_snapshot {
            if !file_snapshot.contains_key(fpath) {
                events.push(FileTelemetry {
                    file_path: fpath.clone(),
                    action: "CREATED".to_string(),
                    file_size_bytes: size,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                });
            } else if file_snapshot[fpath].0 != mtime {
                events.push(FileTelemetry {
                    file_path: fpath.clone(),
                    action: "MODIFIED".to_string(),
                    file_size_bytes: size,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                });
            }
        }
        for fpath in file_snapshot.keys() {
            if !current_snapshot.contains_key(fpath) {
                events.push(FileTelemetry {
                    file_path: fpath.clone(),
                    action: "DELETED".to_string(),
                    file_size_bytes: 0,
                    timestamp: chrono::Utc::now().to_rfc3339(),
                });
            }
        }
    }

    *file_snapshot = current_snapshot;
    events.truncate(30);
    events
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let base_server_url = if args.len() > 1 {
        args[1].trim_end_matches('/').to_string()
    } else {
        env::var("GUARDIAN_SERVER_URL").unwrap_or_else(|_| "http://localhost:4000".to_string())
    };

    println!("╔════════════════════════════════════════════════════════╗");
    println!("║  Guardian EDR Agent v2.0 - Rust Deep Probe (Windows) ║");
    println!("╠════════════════════════════════════════════════════════╣");
    println!("║  Servidor Mestre: {:<37}║", base_server_url);
    println!("╚════════════════════════════════════════════════════════╝");

    let mut sys = System::new_all();
    sys.refresh_all();

    let hostname = sysinfo::System::host_name().unwrap_or_else(|| "Windows-Host".to_string());
    let os_name = sysinfo::System::name().unwrap_or_else(|| "Windows".to_string());
    let os_version = sysinfo::System::os_version().unwrap_or_else(|| "Unknown".to_string());
    let cpu_model = sys.cpus().first().map(|cpu| cpu.brand().to_string()).unwrap_or_else(|| "Unknown CPU".to_string());

    let inventory = SystemInventory {
        hostname: hostname.clone(),
        os_name,
        os_version,
        architecture: env::consts::ARCH.to_string(),
        cpu_model,
        total_memory_mb: sys.total_memory() / (1024 * 1024),
        ip_address: get_primary_ip_address(),
        mac_address: get_real_mac_address(),
    };

    println!("📋 Host: {} | IP: {} | MAC: {}", inventory.hostname, inventory.ip_address, inventory.mac_address);
    println!("📋 OS: {} {} | CPU: {} | RAM: {}MB",
             inventory.os_name, inventory.os_version, inventory.cpu_model, inventory.total_memory_mb);

    // HTTP client without authentication headers for open local lab connectivity.
    let client = reqwest::Client::builder().build()?;

    let register_url = format!("{}/api/v1/agents/register", base_server_url);
    println!("📡 Registering with Guardian Core at {}...", register_url);

    match client.post(&register_url).json(&inventory).send().await {
        Ok(res) => {
            println!("✅ Registration response: {}", res.status());
            if let Ok(body) = res.text().await {
                println!("   Body: {}", body);
            }
        }
        Err(err) => {
            println!("⚠️ Could not reach Guardian Core: {}", err);
            println!("   Running in offline buffer mode.");
        }
    }

    println!("🔄 Entering deep telemetry loop (30s interval)...");
    println!("────────────────────────────────────────────────────────");

    let mut interval = tokio::time::interval(Duration::from_secs(30));
    let mut file_snapshot: HashMap<String, (u64, u64)> = HashMap::new();

    // Seed initial file snapshot (first call won't generate events)
    get_real_file_events(&mut file_snapshot);

    loop {
        interval.tick().await;
        sys.refresh_cpu();
        sys.refresh_memory();
        sys.refresh_processes();

        // ── Deep Process Enumeration with SHA-256, Parent PIDs & Command Lines ──
        let mut top_processes: Vec<ProcessTelemetry> = Vec::new();
        let mut process_list: Vec<(&sysinfo::Pid, &sysinfo::Process)> = sys.processes().iter().collect();
        // Sort by CPU usage descending to get the most active processes
        process_list.sort_by(|a, b| b.1.cpu_usage().partial_cmp(&a.1.cpu_usage()).unwrap_or(std::cmp::Ordering::Equal));

        let mut count = 0;
        for (pid, proc_) in &process_list {
            if count >= 100 {
                break;
            }
            let path_str = proc_.exe().map(|p| p.to_string_lossy().to_string()).unwrap_or_default();
            let command_line = proc_.cmd().join(" ");
            let hash = if !path_str.is_empty() {
                compute_sha256(&path_str)
            } else {
                "N/A".to_string()
            };

            top_processes.push(ProcessTelemetry {
                pid: pid.as_u32(),
                parent_pid: proc_.parent().map(|p| p.as_u32()),
                name: proc_.name().to_string(),
                executable_path: path_str,
                command_line,
                cpu_pct: proc_.cpu_usage(),
                memory_mb: proc_.memory() / (1024 * 1024),
                sha256_hash: hash,
            });
            count += 1;
        }

        // ── Real Network Connections via `netstat -ano` ──
        let network_connections = get_real_network_connections(&sys);

        // ── Real File System Events via Snapshot Polling ──
        let file_events = get_real_file_events(&mut file_snapshot);

        // ── Real Disk Usage ──
        let disk_pct = get_real_disk_usage();

        // ── Deep Security Findings ──
        let security_findings = collect_security_findings(&top_processes, &sys);
        let crit_count = security_findings.iter().filter(|f| f.severity == "CRITICAL").count();
        let high_count = security_findings.iter().filter(|f| f.severity == "HIGH").count();

        let payload = TelemetryPayload {
            agent_id: format!("agent-{}", hostname.to_lowercase()),
            timestamp: chrono::Utc::now().to_rfc3339(),
            cpu_usage_pct: sys.global_cpu_info().cpu_usage(),
            memory_usage_pct: (sys.used_memory() as f32 / sys.total_memory() as f32) * 100.0,
            disk_usage_pct: disk_pct,
            active_processes_count: sys.processes().len(),
            events_count: top_processes.len() + network_connections.len() + file_events.len(),
            top_processes,
            network_connections,
            file_events,
            security_findings,
        };

        println!("💓 [HEARTBEAT] CPU: {:.1}% | RAM: {:.1}% | Disk: {:.1}% | Procs: {} | Socks: {} | Files: {} | Findings: {} (🔴{} 🟠{})",
                 payload.cpu_usage_pct, payload.memory_usage_pct, payload.disk_usage_pct,
                 payload.active_processes_count, payload.network_connections.len(), payload.file_events.len(),
                 payload.security_findings.len(), crit_count, high_count);

        let hb_url = format!("{}/api/v1/agents/heartbeat", base_server_url);
        match client.post(&hb_url).json(&payload).send().await {
            Ok(res) => {
                if !res.status().is_success() {
                    println!("⚠️ Heartbeat response: {}", res.status());
                }
            }
            Err(err) => {
                println!("⚠️ Heartbeat failed: {}", err);
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Deep Windows Security Findings Engine
// ═══════════════════════════════════════════════════════════════════════════

fn collect_security_findings(processes: &[ProcessTelemetry], _sys: &System) -> Vec<SecurityFinding> {
    let mut findings = Vec::new();

    // 1. Process Masquerading Detection [T1036.005]
    let system_bins: Vec<(&str, &str)> = vec![
        ("svchost.exe", "c:\\windows\\system32\\svchost.exe"),
        ("csrss.exe", "c:\\windows\\system32\\csrss.exe"),
        ("lsass.exe", "c:\\windows\\system32\\lsass.exe"),
        ("services.exe", "c:\\windows\\system32\\services.exe"),
        ("winlogon.exe", "c:\\windows\\system32\\winlogon.exe"),
        ("smss.exe", "c:\\windows\\system32\\smss.exe"),
        ("dwm.exe", "c:\\windows\\system32\\dwm.exe"),
    ];
    for proc in processes {
        let name_lower = proc.name.to_lowercase();
        let exe_lower = proc.executable_path.to_lowercase().replace('/', "\\");
        for (bin_name, expected_path) in &system_bins {
            if name_lower == *bin_name && !exe_lower.is_empty() {
                if !exe_lower.contains(expected_path) && !exe_lower.contains("syswow64") {
                    findings.push(SecurityFinding {
                        finding_type: "MASQUERADING".to_string(),
                        severity: "CRITICAL".to_string(),
                        description: format!("{} executando de caminho inesperado", proc.name),
                        evidence: format!("Path: {} (esperado: {})", proc.executable_path, expected_path),
                        mitre_id: "T1036.005".to_string(),
                    });
                }
            }
        }
    }

    // 2. LOLBin Detection [T1218]
    let lolbins = ["certutil.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
                   "bitsadmin.exe", "wscript.exe", "cscript.exe", "msiexec.exe",
                   "installutil.exe", "regasm.exe", "bash.exe"];
    for proc in processes {
        let name_lower = proc.name.to_lowercase();
        if lolbins.contains(&name_lower.as_str()) {
            findings.push(SecurityFinding {
                finding_type: "LOLBIN".to_string(),
                severity: "HIGH".to_string(),
                description: format!("LOLBin em execução: {} (PID {})", proc.name, proc.pid),
                evidence: format!("Path: {}", proc.executable_path),
                mitre_id: "T1218".to_string(),
            });
        }
    }

    // 3. Suspicious Parent-Child Chains [T1059]
    let office_procs = ["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"];
    let shell_procs = ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe"];
    let parent_map: HashMap<u32, &ProcessTelemetry> = processes.iter().map(|p| (p.pid, p)).collect();
    for proc in processes {
        let name_lower = proc.name.to_lowercase();
        if shell_procs.contains(&name_lower.as_str()) {
            if let Some(ppid) = proc.parent_pid {
                if let Some(parent) = parent_map.get(&ppid) {
                    let parent_name = parent.name.to_lowercase();
                    if office_procs.contains(&parent_name.as_str()) {
                        findings.push(SecurityFinding {
                            finding_type: "SUSPICIOUS_CHAIN".to_string(),
                            severity: "HIGH".to_string(),
                            description: format!("Office app \"{}\" gerou shell \"{}\" — possível macro maliciosa", parent.name, proc.name),
                            evidence: format!("Parent PID {} -> Child PID {}", ppid, proc.pid),
                            mitre_id: "T1059".to_string(),
                        });
                    }
                }
            }
        }
        // svchost with wrong parent
        if name_lower == "svchost.exe" {
            if let Some(ppid) = proc.parent_pid {
                if let Some(parent) = parent_map.get(&ppid) {
                    if parent.name.to_lowercase() != "services.exe" {
                        findings.push(SecurityFinding {
                            finding_type: "SUSPICIOUS_CHAIN".to_string(),
                            severity: "CRITICAL".to_string(),
                            description: format!("svchost.exe com pai inesperado: {}", parent.name),
                            evidence: format!("PID {} parent={} ({})", proc.pid, ppid, parent.name),
                            mitre_id: "T1036".to_string(),
                        });
                    }
                }
            }
        }
    }

    // 4. Scheduled Tasks Persistence [T1053.005]
    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("schtasks")
            .args(&["/query", "/fo", "csv", "/nh"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let suspicious_keywords = ["powershell", "cmd.exe", "wscript", "mshta", "certutil", "bitsadmin"];
            for line in stdout.lines() {
                let lower = line.to_lowercase();
                for kw in &suspicious_keywords {
                    if lower.contains(kw) {
                        findings.push(SecurityFinding {
                            finding_type: "SCHEDULED_TASK_PERSISTENCE".to_string(),
                            severity: "WARNING".to_string(),
                            description: format!("Tarefa agendada suspeita contém '{}'", kw),
                            evidence: line.chars().take(120).collect::<String>(),
                            mitre_id: "T1053.005".to_string(),
                        });
                        break;
                    }
                }
            }
        }
    }

    // 5. Registry Run Key Persistence [T1547.001]
    #[cfg(target_os = "windows")]
    {
        let reg_keys = [
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        ];
        for key in &reg_keys {
            if let Ok(output) = std::process::Command::new("reg")
                .args(&["query", key])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let lines: Vec<&str> = stdout.lines()
                    .filter(|l| l.contains("REG_SZ") || l.contains("REG_EXPAND_SZ"))
                    .collect();
                for line in &lines {
                    findings.push(SecurityFinding {
                        finding_type: "REGISTRY_PERSISTENCE".to_string(),
                        severity: "INFO".to_string(),
                        description: format!("Entrada de auto-start no registro: {}", key),
                        evidence: line.trim().chars().take(120).collect::<String>(),
                        mitre_id: "T1547.001".to_string(),
                    });
                }
            }
        }
    }

    // 6. Named Pipe Enumeration [T1570] — detect Cobalt Strike / Metasploit
    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("cmd")
            .args(&["/c", "dir", "\\\\.\\pipe\\"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let suspicious_pipes = ["msagent_", "msse-", "postex_", "status_", "MSSE-", "\\beacon"];
            for line in stdout.lines() {
                let lower = line.to_lowercase();
                for sp in &suspicious_pipes {
                    if lower.contains(&sp.to_lowercase()) {
                        findings.push(SecurityFinding {
                            finding_type: "SUSPICIOUS_NAMED_PIPE".to_string(),
                            severity: "CRITICAL".to_string(),
                            description: format!("Named pipe suspeito (possível C2): {}", sp),
                            evidence: line.trim().chars().take(100).collect::<String>(),
                            mitre_id: "T1570".to_string(),
                        });
                    }
                }
            }
        }
    }

    // 7. DNS Cache Inspection [T1071.004]
    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("ipconfig")
            .args(&["/displaydns"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".onion", ".bit"];
            for line in stdout.lines() {
                if line.contains("Record Name") || line.contains("Nome do Registro") {
                    let lower = line.to_lowercase();
                    for tld in &suspicious_tlds {
                        if lower.contains(tld) {
                            findings.push(SecurityFinding {
                                finding_type: "SUSPICIOUS_DNS".to_string(),
                                severity: "HIGH".to_string(),
                                description: format!("Domínio suspeito no cache DNS (TLD: {})", tld),
                                evidence: line.trim().chars().take(100).collect::<String>(),
                                mitre_id: "T1071.004".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    // 8. PowerShell Obfuscation & DownloadString Analyzer [T1059.001]
    let ps_keywords = ["downloadstring", "downloadfile", "invoke-expression", "iex(", "iex ", "net.webclient", "bitstransfer", "[char[]]", "system.net.sockets"];
    for proc in processes {
        let exe_lower = proc.executable_path.to_lowercase();
        for kw in &ps_keywords {
            if exe_lower.contains(kw) {
                findings.push(SecurityFinding {
                    finding_type: "POWERSHELL_OBFUSCATION".to_string(),
                    severity: "HIGH".to_string(),
                    description: format!("Comando PowerShell obfuscado/download suspeito no PID {}: '{}'", proc.pid, kw),
                    evidence: proc.executable_path.chars().take(120).collect::<String>(),
                    mitre_id: "T1059.001".to_string(),
                });
                break;
            }
        }
    }

    // 9. Windows Defender / AV Status Check [T1562.001]
    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("powershell")
            .args(&["-NoProfile", "-Command", "Get-MpComputerStatus | Select-Object -Property AntivirusEnabled,RealTimeProtectionEnabled,IsTamperProtected | ConvertTo-Json"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
            if stdout.contains("false") {
                findings.push(SecurityFinding {
                    finding_type: "AV_DISABLED".to_string(),
                    severity: "CRITICAL".to_string(),
                    description: "Windows Defender ou proteção em tempo real está DESATIVADO".to_string(),
                    evidence: stdout.chars().take(200).collect::<String>(),
                    mitre_id: "T1562.001".to_string(),
                });
            }
        }
    }

    // 10. Firewall Status Check [T1562.004]
    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("netsh")
            .args(&["advfirewall", "show", "allprofiles", "state"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();
            if stdout.contains("off") || stdout.contains("desativado") {
                findings.push(SecurityFinding {
                    finding_type: "FIREWALL_DISABLED".to_string(),
                    severity: "HIGH".to_string(),
                    description: "Firewall do Windows está DESATIVADO em um ou mais perfis".to_string(),
                    evidence: stdout.chars().take(200).collect::<String>(),
                    mitre_id: "T1562.004".to_string(),
                });
            }
        }
    }

    // 11. Open Shares / SMB Shares [T1021.002]
    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("net")
            .args(&["share"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut share_count = 0;
            for line in stdout.lines() {
                if line.contains(":\\") && !line.contains("$") {
                    share_count += 1;
                    findings.push(SecurityFinding {
                        finding_type: "OPEN_SHARE".to_string(),
                        severity: "WARNING".to_string(),
                        description: "Compartilhamento de rede aberto sem $ (visível)".to_string(),
                        evidence: line.trim().chars().take(120).collect::<String>(),
                        mitre_id: "T1021.002".to_string(),
                    });
                }
            }
            if share_count == 0 {
                for line in stdout.lines() {
                    let l = line.to_lowercase();
                    if l.contains("admin$") || l.contains("c$") || l.contains("ipc$") {
                        findings.push(SecurityFinding {
                            finding_type: "ADMIN_SHARE_ACTIVE".to_string(),
                            severity: "INFO".to_string(),
                            description: "Compartilhamento administrativo padrão ativo".to_string(),
                            evidence: line.trim().chars().take(100).collect::<String>(),
                            mitre_id: "T1021.002".to_string(),
                        });
                    }
                }
            }
        }
    }

    // 12. RDP Status / Remote Desktop Enabled [T1021.001]
    #[cfg(target_os = "windows")]
    {
        if let Ok(output) = std::process::Command::new("reg")
            .args(&["query", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server", "/v", "fDenyTSConnections"])
            .output()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("0x0") {
                findings.push(SecurityFinding {
                    finding_type: "RDP_ENABLED".to_string(),
                    severity: "WARNING".to_string(),
                    description: "Remote Desktop (RDP) está HABILITADO neste host".to_string(),
                    evidence: "fDenyTSConnections = 0x0 (RDP ativo)".to_string(),
                    mitre_id: "T1021.001".to_string(),
                });
            }
        }
    }

    // 13. Startup Folder Items [T1547.001]
    #[cfg(target_os = "windows")]
    {
        let startup_dirs = [
            format!("{}\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", env::var("APPDATA").unwrap_or_default()),
            "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup".to_string(),
        ];
        for dir in &startup_dirs {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.ends_with(".exe") || name.ends_with(".bat") || name.ends_with(".vbs") || name.ends_with(".ps1") || name.ends_with(".cmd") {
                        findings.push(SecurityFinding {
                            finding_type: "STARTUP_ITEM".to_string(),
                            severity: "WARNING".to_string(),
                            description: format!("Executável na pasta Startup: {}", name),
                            evidence: entry.path().to_string_lossy().chars().take(150).collect::<String>(),
                            mitre_id: "T1547.001".to_string(),
                        });
                    }
                }
            }
        }
    }

    // 14. Hosts File Tampering [T1565.001]
    #[cfg(target_os = "windows")]
    {
        let hosts_path = "C:\\Windows\\System32\\drivers\\etc\\hosts";
        if let Ok(content) = fs::read_to_string(hosts_path) {
            let mut custom_entries = 0;
            for line in content.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') && !trimmed.contains("localhost") {
                    custom_entries += 1;
                    if custom_entries <= 5 {
                        findings.push(SecurityFinding {
                            finding_type: "HOSTS_TAMPERED".to_string(),
                            severity: "WARNING".to_string(),
                            description: "Entrada customizada no arquivo HOSTS (possível DNS hijacking)".to_string(),
                            evidence: trimmed.chars().take(100).collect::<String>(),
                            mitre_id: "T1565.001".to_string(),
                        });
                    }
                }
            }
        }
    }

    findings.truncate(80);
    findings
}
