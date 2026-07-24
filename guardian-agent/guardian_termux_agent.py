#!/usr/bin/env python3
"""
Guardian EDR/NDR - Deep Android/Linux Real Telemetry Agent v10.0
=============================================================
DEEP SECURITY FINDINGS:
  * Root/Su/Magisk detection           * SELinux enforcement
  * ADB/USB debug state                * Suspicious ELF/APK scanning
  * Kernel module rootkit detection     * Crontab persistence
  * SSH authorized_keys audit           * LD_PRELOAD hijack
  * Open listening port self-scan       * TracerPid debugger checks
"""

import sys
import time
import json
import socket
import urllib.request
import os
import platform
import struct
import hashlib
import glob

VALID_AGENT_TOKEN = "GUARDIAN-SECRET-AGENT-KEY-v0.9"

# ─── CPU Usage (Delta /proc/stat) ───────────────────────────────────────────

_prev_cpu_idle = 0
_prev_cpu_total = 0

def get_real_cpu_usage():
    """Calculate real CPU % from /proc/stat using delta between two reads."""
    global _prev_cpu_idle, _prev_cpu_total
    try:
        with open('/proc/stat', 'r') as f:
            line = f.readline()  # cpu  user nice system idle iowait irq softirq steal
        parts = line.split()
        if parts[0] != 'cpu':
            return 0.0
        vals = [int(v) for v in parts[1:]]
        idle = vals[3] + (vals[4] if len(vals) > 4 else 0)  # idle + iowait
        total = sum(vals)

        d_idle = idle - _prev_cpu_idle
        d_total = total - _prev_cpu_total
        _prev_cpu_idle = idle
        _prev_cpu_total = total

        if d_total == 0:
            return 0.0
        return round((1.0 - d_idle / d_total) * 100.0, 1)
    except Exception:
        return 0.0


# ─── Memory from /proc/meminfo ──────────────────────────────────────────────

def get_real_ram_usage():
    """Read real memory stats from /proc/meminfo. Returns (used_pct, total_mb)."""
    try:
        if not os.path.exists('/proc/meminfo'):
            return 0.0, 0.0
        mem = {}
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    mem[parts[0].rstrip(':')] = int(parts[1])
        total = mem.get('MemTotal', 0)
        available = mem.get('MemAvailable', 0)
        free = mem.get('MemFree', 0)
        buffers = mem.get('Buffers', 0)
        cached = mem.get('Cached', 0)
        if total == 0:
            return 0.0, 0.0
        # MemAvailable is the best metric; fall back to free+buffers+cached
        if available > 0:
            used = total - available
        else:
            used = total - free - buffers - cached
        return round((used / total) * 100.0, 1), round(total / 1024.0, 0)
    except Exception:
        return 0.0, 0.0


# ─── Disk Usage via os.statvfs ───────────────────────────────────────────────

def get_real_disk_usage():
    """Get real disk usage % using statvfs on / or /storage/emulated."""
    for mount in ['/storage/emulated/0', '/sdcard', '/data', '/']:
        try:
            st = os.statvfs(mount)
            total = st.f_blocks * st.f_frsize
            free = st.f_bfree * st.f_frsize
            if total == 0:
                continue
            used_pct = round(((total - free) / total) * 100.0, 1)
            return used_pct
        except Exception:
            continue
    return 0.0


# ─── SHA-256 Hash of Executables ─────────────────────────────────────────────

def compute_sha256(filepath, max_bytes=1048576):
    """Compute SHA-256 of a file (reads up to max_bytes for speed)."""
    try:
        if not os.path.isfile(filepath) or not os.access(filepath, os.R_OK):
            return "ACCESS_DENIED"
        h = hashlib.sha256()
        read = 0
        with open(filepath, 'rb') as f:
            while read < max_bytes:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
                read += len(chunk)
        return h.hexdigest()
    except Exception:
        return "ACCESS_DENIED"


# ─── Processes from /proc/[pid] ──────────────────────────────────────────────

def get_real_processes():
    """Enumerate live processes from /proc/[pid] with per-process CPU, RSS, exe path, and SHA-256."""
    processes = []
    try:
        all_pids = [p for p in os.listdir('/proc') if p.isdigit()]
        total_count = len(all_pids)
        hz = os.sysconf('SC_CLK_TCK') if hasattr(os, 'sysconf') else 100

        collected = 0
        for pid_str in all_pids:
            if collected >= 30:
                break
            pid = int(pid_str)
            proc_dir = f'/proc/{pid_str}'

            # Read process name and exe path from cmdline
            name = f'pid-{pid}'
            exe_path = ''
            try:
                with open(f'{proc_dir}/cmdline', 'rb') as f:
                    content = f.read(512).replace(b'\x00', b' ').decode('utf-8', errors='ignore').strip()
                    if content:
                        name = os.path.basename(content.split()[0])
                        exe_path = content.split()[0]
            except Exception:
                pass

            # Try to resolve real exe via symlink
            if not exe_path:
                try:
                    exe_path = os.readlink(f'{proc_dir}/exe')
                except Exception:
                    exe_path = f'/proc/{pid_str}/exe'

            # Read CPU time from /proc/[pid]/stat
            cpu_pct = 0.0
            try:
                with open(f'{proc_dir}/stat', 'r') as f:
                    stat_parts = f.read().split()
                    # Fields: pid (comm) state ppid ... utime(13) stime(14)
                    if len(stat_parts) > 14:
                        utime = int(stat_parts[13])
                        stime = int(stat_parts[14])
                        total_ticks = utime + stime
                        # Rough instantaneous CPU estimate
                        cpu_pct = round(total_ticks / (hz * max(1, (time.time() % 3600))), 2)
            except Exception:
                pass

            # Read RSS from /proc/[pid]/status
            memory_mb = 0
            parent_pid = None
            try:
                with open(f'{proc_dir}/status', 'r') as f:
                    for line in f:
                        if line.startswith('VmRSS:'):
                            memory_mb = int(line.split()[1]) // 1024  # kB -> MB
                        elif line.startswith('PPid:'):
                            parent_pid = int(line.split()[1])
            except Exception:
                pass

            # SHA-256 of executable binary
            sha = compute_sha256(exe_path)

            processes.append({
                "pid": pid,
                "parentPid": parent_pid,
                "name": name,
                "executablePath": exe_path,
                "cpuPct": cpu_pct,
                "memoryMb": memory_mb,
                "sha256Hash": sha
            })
            collected += 1

        return processes, total_count
    except Exception as e:
        return [{
            "pid": os.getpid(),
            "parentPid": os.getppid(),
            "name": "guardian-agent",
            "executablePath": sys.executable,
            "cpuPct": 0.0,
            "memoryMb": 0,
            "sha256Hash": compute_sha256(sys.executable)
        }], 1


# ─── Network Sockets from /proc/net/{tcp,tcp6,udp,udp6} ─────────────────────

def _decode_hex_ip_port(hex_str):
    """Decode kernel hex IP:PORT from /proc/net/tcp. Handles little-endian IPv4."""
    try:
        ip_hex, port_hex = hex_str.split(':')
        port = int(port_hex, 16)
        # IPv4: 4 bytes little-endian
        if len(ip_hex) == 8:
            ip_int = int(ip_hex, 16)
            ip_bytes = struct.pack('<I', ip_int)
            ip_str = '.'.join(str(b) for b in ip_bytes)
        else:
            ip_str = ip_hex  # IPv6 - return raw
        return ip_str, port
    except Exception:
        return '0.0.0.0', 0

_TCP_STATES = {
    '01': 'ESTABLISHED', '02': 'SYN_SENT', '03': 'SYN_RECV',
    '04': 'FIN_WAIT1', '05': 'FIN_WAIT2', '06': 'TIME_WAIT',
    '07': 'CLOSE', '08': 'CLOSE_WAIT', '09': 'LAST_ACK',
    '0A': 'LISTEN', '0B': 'CLOSING'
}

def _read_proc_net_file(filepath, protocol):
    """Parse a /proc/net/{tcp,udp} file into structured socket records."""
    sockets = []
    try:
        with open(filepath, 'r') as f:
            lines = f.readlines()[1:]  # skip header
        for line in lines:
            parts = line.strip().split()
            if len(parts) < 10:
                continue
            local_ip, local_port = _decode_hex_ip_port(parts[1])
            remote_ip, remote_port = _decode_hex_ip_port(parts[2])
            state_hex = parts[3]
            state = _TCP_STATES.get(state_hex, 'UNKNOWN')
            # UID is at index 7, inode at 9
            uid = int(parts[7]) if len(parts) > 7 else 0
            inode = parts[9] if len(parts) > 9 else '0'

            # Skip loopback-only entries
            if local_ip == '127.0.0.1' and remote_ip == '127.0.0.1':
                continue

            sockets.append({
                "pid": 0,  # Resolved below via /proc/[pid]/fd
                "processName": f"uid-{uid}",
                "protocol": protocol,
                "localAddress": local_ip,
                "localPort": local_port,
                "remoteAddress": remote_ip,
                "remotePort": remote_port,
                "status": state,
                "inode": inode
            })
    except Exception:
        pass
    return sockets

def _resolve_socket_pids(sockets):
    """Try to resolve PIDs for sockets by scanning /proc/[pid]/fd symlinks."""
    inode_to_pid = {}
    try:
        for pid_str in os.listdir('/proc'):
            if not pid_str.isdigit():
                continue
            fd_dir = f'/proc/{pid_str}/fd'
            try:
                for fd in os.listdir(fd_dir):
                    try:
                        link = os.readlink(f'{fd_dir}/{fd}')
                        if link.startswith('socket:['):
                            inode = link[8:-1]
                            inode_to_pid[inode] = int(pid_str)
                    except Exception:
                        continue
            except Exception:
                continue
    except Exception:
        pass

    # Also build PID->name mapping
    pid_name = {}
    for pid_val in set(inode_to_pid.values()):
        try:
            with open(f'/proc/{pid_val}/cmdline', 'rb') as f:
                cmd = f.read(256).replace(b'\x00', b' ').decode('utf-8', errors='ignore').strip()
                if cmd:
                    pid_name[pid_val] = os.path.basename(cmd.split()[0])
        except Exception:
            pass

    for sock in sockets:
        inode = sock.get('inode', '0')
        if inode in inode_to_pid:
            pid = inode_to_pid[inode]
            sock['pid'] = pid
            sock['processName'] = pid_name.get(pid, f'pid-{pid}')
        # Remove internal inode field
        sock.pop('inode', None)


def get_real_sockets():
    """Read ALL real network sockets from /proc/net/{tcp,tcp6,udp,udp6}."""
    all_sockets = []
    for fname, proto in [('/proc/net/tcp', 'TCP'), ('/proc/net/tcp6', 'TCP6'),
                         ('/proc/net/udp', 'UDP'), ('/proc/net/udp6', 'UDP6')]:
        all_sockets.extend(_read_proc_net_file(fname, proto))

    # Resolve PIDs
    _resolve_socket_pids(all_sockets)

    # Limit to 50 most interesting sockets (ESTABLISHED first, then LISTEN)
    priority = {'ESTABLISHED': 0, 'SYN_SENT': 1, 'LISTEN': 2}
    all_sockets.sort(key=lambda s: priority.get(s['status'], 5))
    return all_sockets[:50]


# ─── File Events via Polling /sdcard and /data ───────────────────────────────

_file_snapshot = {}

def get_real_file_events():
    """Detect real file changes by comparing mtime snapshots on key directories."""
    global _file_snapshot
    events = []
    watch_dirs = ['/sdcard/Download', '/sdcard/DCIM', '/data/data', '/tmp',
                  '/storage/emulated/0/Download']

    current_snapshot = {}
    for d in watch_dirs:
        try:
            if not os.path.isdir(d):
                continue
            for entry in os.scandir(d):
                try:
                    if entry.is_file(follow_symlinks=False):
                        stat = entry.stat()
                        key = entry.path
                        current_snapshot[key] = (stat.st_mtime, stat.st_size)
                except Exception:
                    continue
        except Exception:
            continue

    # Compare with previous snapshot
    if _file_snapshot:
        for fpath, (mtime, size) in current_snapshot.items():
            if fpath not in _file_snapshot:
                events.append({
                    "filePath": fpath,
                    "action": "CREATED",
                    "fileSizeBytes": size,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(mtime))
                })
            elif _file_snapshot[fpath][0] != mtime:
                events.append({
                    "filePath": fpath,
                    "action": "MODIFIED",
                    "fileSizeBytes": size,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(mtime))
                })
        for fpath in _file_snapshot:
            if fpath not in current_snapshot:
                events.append({
                    "filePath": fpath,
                    "action": "DELETED",
                    "fileSizeBytes": 0,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                })

    _file_snapshot = current_snapshot
    return events[:30]  # Cap at 30 events per heartbeat


# ─── MAC Address from /sys/class/net ─────────────────────────────────────────

def get_real_mac_address():
    """Read real MAC from /sys/class/net/<iface>/address."""
    try:
        for iface in ['wlan0', 'eth0', 'wlan1', 'rmnet0']:
            mac_path = f'/sys/class/net/{iface}/address'
            if os.path.exists(mac_path):
                with open(mac_path, 'r') as f:
                    mac = f.read().strip()
                    if mac and mac != '00:00:00:00:00:00':
                        return mac.upper()
    except Exception:
        pass
    return "02:00:00:00:00:00"


# ─── Primary IP Detection ───────────────────────────────────────────────────

def get_primary_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


# ─── System Inventory ───────────────────────────────────────────────────────

def get_system_inventory():
    hostname = socket.gethostname() or "Android-Termux"
    _, total_mem_mb = get_real_ram_usage()

    # Detect Android version
    android_ver = ""
    try:
        with open('/system/build.prop', 'r') as f:
            for line in f:
                if 'ro.build.version.release' in line:
                    android_ver = line.split('=')[1].strip()
                    break
    except Exception:
        pass

    os_name = f"Android {android_ver}" if android_ver else f"Android ({platform.system()})"

    # Detect CPU model from /proc/cpuinfo
    cpu_model = "ARM Cortex / Unknown"
    try:
        with open('/proc/cpuinfo', 'r') as f:
            for line in f:
                if line.startswith('Hardware') or line.startswith('model name'):
                    cpu_model = line.split(':')[1].strip()
                    break
    except Exception:
        pass

    return {
        "hostname": f"Android-{hostname}",
        "osName": os_name,
        "osVersion": platform.release() or "Termux",
        "architecture": platform.machine() or "aarch64",
        "cpuModel": cpu_model,
        "totalMemoryMb": int(total_mem_mb),
        "ipAddress": get_primary_ip(),
        "macAddress": get_real_mac_address()
    }


# ─── DEEP SECURITY FINDINGS ENGINE ──────────────────────────────────────────

def detect_root_su():
    """Detect rooted device: su, busybox, magisk, supersu binaries."""
    findings = []
    root_paths = [
        '/system/xbin/su', '/system/bin/su', '/sbin/su', '/data/local/tmp/su',
        '/system/xbin/busybox', '/system/bin/busybox', '/sbin/busybox',
        '/system/xbin/magisk', '/sbin/magisk', '/data/adb/magisk',
        '/system/app/Superuser.apk', '/system/app/SuperSU',
        '/data/data/com.topjohnwu.magisk', '/data/data/eu.chainfire.supersu',
    ]
    found = [p for p in root_paths if os.path.exists(p)]
    if found:
        findings.append({
            "findingType": "ROOT_DETECTION",
            "severity": "CRITICAL",
            "description": f"Dispositivo com root detectado: {len(found)} binários root encontrados",
            "evidence": ", ".join(found[:5]),
            "mitreId": "T1398"
        })
    return findings

def detect_selinux_status():
    """Check SELinux enforcement status."""
    findings = []
    try:
        enforce_path = '/sys/fs/selinux/enforce'
        if os.path.exists(enforce_path):
            with open(enforce_path, 'r') as f:
                val = f.read().strip()
            if val == '0':
                findings.append({
                    "findingType": "SELINUX_PERMISSIVE",
                    "severity": "HIGH",
                    "description": "SELinux em modo PERMISSIVE — proteção reduzida",
                    "evidence": "/sys/fs/selinux/enforce = 0",
                    "mitreId": "T1629"
                })
        elif not os.path.exists('/sys/fs/selinux'):
            findings.append({
                "findingType": "SELINUX_DISABLED",
                "severity": "CRITICAL",
                "description": "SELinux completamente desabilitado",
                "evidence": "/sys/fs/selinux não existe",
                "mitreId": "T1629"
            })
    except Exception:
        pass
    return findings

def detect_adb_debug():
    """Detect ADB/USB debugging enabled."""
    findings = []
    try:
        # Check build.prop
        if os.path.exists('/system/build.prop'):
            with open('/system/build.prop', 'r') as f:
                content = f.read()
            if 'ro.debuggable=1' in content:
                findings.append({
                    "findingType": "ADB_DEBUG_ENABLED",
                    "severity": "WARNING",
                    "description": "Dispositivo em modo debuggable (ro.debuggable=1)",
                    "evidence": "ro.debuggable=1 em /system/build.prop",
                    "mitreId": "T1404"
                })
            if 'ro.adb.secure=0' in content:
                findings.append({
                    "findingType": "ADB_INSECURE",
                    "severity": "HIGH",
                    "description": "ADB sem autenticação (ro.adb.secure=0)",
                    "evidence": "ro.adb.secure=0 em /system/build.prop",
                    "mitreId": "T1404"
                })
    except Exception:
        pass
    # Check if ADB TCP port is open (5555)
    try:
        with open('/proc/net/tcp', 'r') as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 4:
                    local_hex = parts[1]
                    if ':' in local_hex:
                        port = int(local_hex.split(':')[1], 16)
                        state = parts[3]
                        if port == 5555 and state == '0A':  # LISTEN
                            findings.append({
                                "findingType": "ADB_TCP_EXPOSED",
                                "severity": "CRITICAL",
                                "description": "ADB sobre TCP porta 5555 exposto na rede",
                                "evidence": "Porta 5555 em estado LISTEN em /proc/net/tcp",
                                "mitreId": "T1404"
                            })
    except Exception:
        pass
    return findings

def detect_suspicious_binaries():
    """Scan for ELF binaries, .sh scripts, .apk files in suspicious locations."""
    findings = []
    scan_dirs = ['/data/local/tmp', '/sdcard/Download', '/tmp', '/dev/shm']
    suspicious_count = 0
    evidence_files = []
    for d in scan_dirs:
        try:
            if not os.path.isdir(d):
                continue
            for entry in os.scandir(d):
                try:
                    if not entry.is_file():
                        continue
                    name = entry.name.lower()
                    is_suspicious = False
                    if name.endswith(('.sh', '.apk', '.dex', '.so', '.bin', '.elf', '.payload')):
                        is_suspicious = True
                    elif os.access(entry.path, os.X_OK):
                        # Check ELF magic
                        try:
                            with open(entry.path, 'rb') as f:
                                magic = f.read(4)
                            if magic == b'\x7fELF':
                                is_suspicious = True
                        except Exception:
                            pass
                    if is_suspicious:
                        suspicious_count += 1
                        sha = compute_sha256(entry.path)
                        evidence_files.append(f"{entry.path} (SHA:{sha[:16]}...)")
                except Exception:
                    continue
        except Exception:
            continue
    if suspicious_count > 0:
        findings.append({
            "findingType": "SUSPICIOUS_BINARY",
            "severity": "HIGH",
            "description": f"{suspicious_count} binários/scripts suspeitos encontrados em diretórios temporários",
            "evidence": "; ".join(evidence_files[:5]),
            "mitreId": "T1476"
        })
    return findings

def detect_kernel_modules():
    """Read /proc/modules for loaded kernel modules (rootkit detection)."""
    findings = []
    suspicious_modules = ['rootkit', 'hide', 'stealth', 'diamorphine', 'reptile', 'bdvl', 'knull']
    try:
        if os.path.exists('/proc/modules'):
            with open('/proc/modules', 'r') as f:
                modules = f.readlines()
            for mod_line in modules:
                mod_name = mod_line.split()[0].lower() if mod_line.strip() else ''
                for susp in suspicious_modules:
                    if susp in mod_name:
                        findings.append({
                            "findingType": "SUSPICIOUS_KERNEL_MODULE",
                            "severity": "CRITICAL",
                            "description": f"Módulo kernel suspeito detectado: {mod_name}",
                            "evidence": mod_line.strip()[:100],
                            "mitreId": "T1014"
                        })
    except Exception:
        pass
    return findings

def detect_crontab_persistence():
    """Check crontab entries for persistence."""
    findings = []
    cron_paths = [
        '/var/spool/cron/crontabs/root', '/var/spool/cron/root',
        '/etc/crontab', '/etc/cron.d',
    ]
    for cp in cron_paths:
        try:
            if os.path.isfile(cp):
                with open(cp, 'r') as f:
                    content = f.read()
                lines = [l.strip() for l in content.split('\n') if l.strip() and not l.startswith('#')]
                if lines:
                    findings.append({
                        "findingType": "CRONTAB_PERSISTENCE",
                        "severity": "WARNING",
                        "description": f"Entradas crontab detectadas em {cp}: {len(lines)} tarefas",
                        "evidence": lines[0][:100],
                        "mitreId": "T1053.003"
                    })
            elif os.path.isdir(cp):
                entries = os.listdir(cp)
                if entries:
                    findings.append({
                        "findingType": "CRONTAB_PERSISTENCE",
                        "severity": "WARNING",
                        "description": f"Diretório cron.d contém {len(entries)} arquivos",
                        "evidence": ", ".join(entries[:5]),
                        "mitreId": "T1053.003"
                    })
        except Exception:
            continue
    return findings

def detect_ssh_authorized_keys():
    """Check for SSH authorized_keys files."""
    findings = []
    home_dirs = ['/root', '/home', os.path.expanduser('~')]
    for home in home_dirs:
        ak_path = os.path.join(home, '.ssh', 'authorized_keys')
        try:
            if os.path.isfile(ak_path):
                with open(ak_path, 'r') as f:
                    keys = [l.strip() for l in f.readlines() if l.strip() and not l.startswith('#')]
                if keys:
                    findings.append({
                        "findingType": "SSH_AUTHORIZED_KEYS",
                        "severity": "WARNING",
                        "description": f"{len(keys)} chaves SSH autorizadas em {ak_path}",
                        "evidence": keys[0][:80] + "...",
                        "mitreId": "T1098.004"
                    })
        except Exception:
            continue
    return findings

def detect_ld_preload_hijack():
    """Check LD_PRELOAD env and /etc/ld.so.preload for library injection."""
    findings = []
    # Check environment
    ld_preload = os.environ.get('LD_PRELOAD', '')
    if ld_preload:
        findings.append({
            "findingType": "LD_PRELOAD_HIJACK",
            "severity": "CRITICAL",
            "description": "LD_PRELOAD definido — possível injeção de biblioteca",
            "evidence": f"LD_PRELOAD={ld_preload}",
            "mitreId": "T1574.006"
        })
    # Check /etc/ld.so.preload
    try:
        if os.path.isfile('/etc/ld.so.preload'):
            with open('/etc/ld.so.preload', 'r') as f:
                content = f.read().strip()
            if content:
                findings.append({
                    "findingType": "LD_PRELOAD_FILE",
                    "severity": "CRITICAL",
                    "description": "Arquivo /etc/ld.so.preload encontrado com conteúdo",
                    "evidence": content[:100],
                    "mitreId": "T1574.006"
                })
    except Exception:
        pass
    return findings

def detect_listening_ports():
    """Self-scan for open LISTEN ports on this device."""
    findings = []
    listen_ports = []
    try:
        with open('/proc/net/tcp', 'r') as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 4 and parts[3] == '0A':  # LISTEN
                    port = int(parts[1].split(':')[1], 16)
                    if port > 0:
                        listen_ports.append(port)
    except Exception:
        pass
    try:
        with open('/proc/net/tcp6', 'r') as f:
            for line in f.readlines()[1:]:
                parts = line.strip().split()
                if len(parts) >= 4 and parts[3] == '0A':
                    port = int(parts[1].split(':')[1], 16)
                    if port > 0 and port not in listen_ports:
                        listen_ports.append(port)
    except Exception:
        pass
    dangerous_ports = {21: 'FTP', 22: 'SSH', 23: 'Telnet', 80: 'HTTP', 8080: 'HTTP-Alt',
                       5555: 'ADB', 4444: 'Meterpreter', 6667: 'IRC', 3306: 'MySQL',
                       1337: 'Backdoor', 31337: 'Backdoor'}
    for port in listen_ports:
        if port in dangerous_ports:
            findings.append({
                "findingType": "EXPOSED_PORT",
                "severity": "HIGH" if port in (23, 4444, 5555, 1337, 31337) else "WARNING",
                "description": f"Porta {port} ({dangerous_ports[port]}) aberta em LISTEN neste dispositivo",
                "evidence": f"Porta {port} detectada em /proc/net/tcp",
                "mitreId": "T1421"
            })
    if listen_ports:
        findings.append({
            "findingType": "LISTENING_PORTS_AUDIT",
            "severity": "INFO",
            "description": f"{len(listen_ports)} portas em LISTEN neste dispositivo",
            "evidence": ", ".join(str(p) for p in sorted(listen_ports)[:15]),
            "mitreId": "T1421"
        })
    return findings

def detect_environment_integrity():
    """Check TracerPid (debugger), /proc/self/maps for injected libs."""
    findings = []
    # TracerPid check
    try:
        with open('/proc/self/status', 'r') as f:
            for line in f:
                if line.startswith('TracerPid:'):
                    tracer = int(line.split(':')[1].strip())
                    if tracer != 0:
                        findings.append({
                            "findingType": "DEBUGGER_ATTACHED",
                            "severity": "CRITICAL",
                            "description": f"Debugger/ptrace anexado ao processo (TracerPid={tracer})",
                            "evidence": f"TracerPid: {tracer} em /proc/self/status",
                            "mitreId": "T1622"
                        })
                    break
    except Exception:
        pass
    # Check for injected libraries in /proc/self/maps
    suspicious_libs = ['frida', 'xposed', 'substrate', 'inject', 'hook', 'cydia']
    try:
        with open('/proc/self/maps', 'r') as f:
            for line in f:
                low = line.lower()
                for susp in suspicious_libs:
                    if susp in low:
                        findings.append({
                            "findingType": "INJECTED_LIBRARY",
                            "severity": "CRITICAL",
                            "description": f"Biblioteca suspeita detectada na memória: {susp}",
                            "evidence": line.strip()[:100],
                            "mitreId": "T1625"
                        })
                        break
    except Exception:
        pass
    return findings

def collect_all_security_findings():
    """Run all deep security detection modules."""
    all_findings = []
    all_findings.extend(detect_root_su())
    all_findings.extend(detect_selinux_status())
    all_findings.extend(detect_adb_debug())
    all_findings.extend(detect_suspicious_binaries())
    all_findings.extend(detect_kernel_modules())
    all_findings.extend(detect_crontab_persistence())
    all_findings.extend(detect_ssh_authorized_keys())
    all_findings.extend(detect_ld_preload_hijack())
    all_findings.extend(detect_listening_ports())
    all_findings.extend(detect_environment_integrity())
    return all_findings


# ─── HTTP POST Helper ───────────────────────────────────────────────────────

def send_post_request(url, data):
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode('utf-8'),
        headers={
            "Content-Type": "application/json",
            "x-guardian-token": VALID_AGENT_TOKEN
        },
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        return response.read().decode('utf-8')


# ─── Main Agent Loop ────────────────────────────────────────────────────────

def main():
    if len(sys.argv) > 1:
        server_ip = sys.argv[1]
    else:
        server_ip = input("Digite o IP da maquina mestre (ex: 192.168.50.140): ").strip()

    if not server_ip.startswith("http"):
        server_url = f"http://{server_ip}:4000"
    else:
        server_url = server_ip

    print(f"╔════════════════════════════════════════════════════════╗")
    print(f"║  Guardian EDR Agent v9.0 - Android/Linux Deep Probe  ║")
    print(f"╠════════════════════════════════════════════════════════╣")
    print(f"║  Servidor Mestre: {server_url:<37s}║")
    print(f"╚════════════════════════════════════════════════════════╝")

    inventory = get_system_inventory()
    hostname = inventory["hostname"]
    agent_id = f"agent-{hostname.lower()}"

    print(f"[INVENTORY] Host: {hostname} | IP: {inventory['ipAddress']} | MAC: {inventory['macAddress']}")
    print(f"[INVENTORY] OS: {inventory['osName']} | CPU: {inventory['cpuModel']} | RAM: {inventory['totalMemoryMb']}MB")

    # 1. Register Agent
    try:
        res = send_post_request(f"{server_url}/api/v1/agents/register", inventory)
        print(f"[OK] Registrado com sucesso no servidor mestre")
    except Exception as e:
        print(f"[WARN] Erro ao registrar: {e}")

    # 2. Seed initial CPU reading
    get_real_cpu_usage()
    time.sleep(1)

    # 3. Seed initial file snapshot (first call won't generate events)
    get_real_file_events()

    # 4. Telemetry Loop
    print("[LOOP] Enviando telemetria profunda a cada 30s...")
    print("─" * 56)

    while True:
        try:
            cpu_pct = get_real_cpu_usage()
            ram_pct, _ = get_real_ram_usage()
            disk_pct = get_real_disk_usage()
            top_procs, proc_count = get_real_processes()
            sockets = get_real_sockets()
            file_events = get_real_file_events()
            security_findings = collect_all_security_findings()

            payload = {
                "agentId": agent_id,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "cpuUsagePct": cpu_pct,
                "memoryUsagePct": ram_pct,
                "diskUsagePct": disk_pct,
                "activeProcessesCount": proc_count,
                "eventsCount": len(top_procs) + len(sockets) + len(file_events),
                "topProcesses": top_procs,
                "networkConnections": sockets,
                "fileEvents": file_events,
                "securityFindings": security_findings
            }

            res = send_post_request(f"{server_url}/api/v1/agents/heartbeat", payload)
            crit = len([f for f in security_findings if f['severity'] == 'CRITICAL'])
            high = len([f for f in security_findings if f['severity'] == 'HIGH'])
            print(f"[HEARTBEAT] CPU: {cpu_pct}% | RAM: {ram_pct}% | Disk: {disk_pct}% | "
                  f"Procs: {proc_count} | Socks: {len(sockets)} | Files: {len(file_events)} | "
                  f"Findings: {len(security_findings)} (🔴{crit} 🟠{high})")
        except Exception as e:
            print(f"[WARN] Heartbeat falhou: {e}")

        time.sleep(30)

if __name__ == "__main__":
    main()
