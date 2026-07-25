#!/usr/bin/env python3
"""
Guardian EDR/NDR - Deep Android/Linux Real Telemetry Agent v12.0
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
import subprocess
import re

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


# ─── UID to Android Package Resolver ──────────────────────────────────────────

_UID_PACKAGE_CACHE = {}
_LAST_UID_CACHE_TIME = 0

def get_uid_package_map():
    """Build a mapping from Android UIDs (e.g. 10145) to Package Names (e.g. com.whatsapp)."""
    global _UID_PACKAGE_CACHE, _LAST_UID_CACHE_TIME
    now = time.time()
    if _UID_PACKAGE_CACHE and (now - _LAST_UID_CACHE_TIME < 60):
        return _UID_PACKAGE_CACHE

    mapping = {0: 'root', 1000: 'system', 1001: 'telephony', 1002: 'bluetooth', 1023: 'media_rw'}
    try:
        if os.path.exists('/data/system/packages.list') and os.access('/data/system/packages.list', os.R_OK):
            with open('/data/system/packages.list', 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        mapping[int(parts[1])] = parts[0]
    except Exception:
        pass

    if len(mapping) <= 5:
        try:
            res = subprocess.run(['pm', 'list', 'packages', '-U'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=3)
            if res.returncode == 0 and res.stdout:
                for line in res.stdout.splitlines():
                    m = re.search(r'package:([^\s]+)\s+uid:(\d+)', line)
                    if m:
                        pkg, uid_str = m.groups()
                        mapping[int(uid_str)] = pkg
        except Exception:
            pass

    _UID_PACKAGE_CACHE = mapping
    _LAST_UID_CACHE_TIME = now
    return mapping



def _read_proc_status(pid_str):
    """Read PPID/UID from /proc/[pid]/status when Android permissions allow it."""
    info = {"ppid": None, "uid": None}
    try:
        with open(f'/proc/{pid_str}/status', 'r') as f:
            for line in f:
                if line.startswith('PPid:'):
                    parts = line.split()
                    if len(parts) > 1 and parts[1].isdigit():
                        info["ppid"] = int(parts[1])
                elif line.startswith('Uid:'):
                    parts = line.split()
                    if len(parts) > 1 and parts[1].isdigit():
                        info["uid"] = int(parts[1])
    except Exception:
        pass
    return info

def _add_process(processes, seen_pids, seen_names, pid, name, exe_path='', parent_pid=None, memory_mb=None, uid=None):
    """Normalize and append one process, avoiding helper noise and duplicate PIDs."""
    if not pid or pid in seen_pids or pid == os.getpid():
        return
    name = (name or '').strip()
    exe_path = (exe_path or '').strip()
    if not name and exe_path:
        name = os.path.basename(exe_path.split()[0])
    if not name or name in ('ps', 'sh', 'cat', 'stty', '-b', 'zombie') or name.startswith('pid-'):
        return

    pid_str = str(pid)
    status = _read_proc_status(pid_str)
    if parent_pid is None:
        parent_pid = status.get('ppid')
    if uid is None:
        uid = status.get('uid')
    uid_map = get_uid_package_map()
    package_name = uid_map.get(uid) if uid is not None else None

    if not exe_path:
        try:
            with open(f'/proc/{pid_str}/cmdline', 'rb') as f:
                cmd = f.read(512).replace(b'\x00', b' ').decode('utf-8', errors='ignore').strip()
                if cmd:
                    exe_path = cmd.split()[0]
        except Exception:
            pass
    if not exe_path:
        try:
            exe_path = os.readlink(f'/proc/{pid_str}/exe')
        except Exception:
            exe_path = f'/data/app/{name}' if name.startswith('com.') else f'/proc/{pid_str}/exe'

    if memory_mb is None:
        memory_mb = get_proc_memory_mb(pid_str)

    display_name = package_name if package_name and name.startswith('app_process') else name
    seen_pids.add(pid)
    seen_names.add(display_name)
    processes.append({
        "pid": pid,
        "parentPid": parent_pid,
        "name": display_name,
        "executablePath": exe_path,
        "cpuPct": 0.0,
        "memoryMb": memory_mb or 0.0,
        "sha256Hash": "ANDROID_PACKAGE" if (display_name.startswith('com.') or package_name) else compute_sha256(exe_path)
    })

def _parse_ps_table(output):
    """Parse Android toybox/toolbox ps output using its header positions."""
    rows = []
    lines = [line for line in output.splitlines() if line.strip()]
    if len(lines) < 2:
        return rows
    header = lines[0].split()
    upper = [h.upper() for h in header]
    pid_idx = upper.index('PID') if 'PID' in upper else None
    ppid_idx = upper.index('PPID') if 'PPID' in upper else None
    name_idx = None
    for candidate in ('NAME', 'CMD', 'COMMAND', 'ARGS'):
        if candidate in upper:
            name_idx = upper.index(candidate)
            break
    if pid_idx is None:
        return rows
    for line in lines[1:]:
        parts = line.split(None, max(len(header) - 1, 1))
        if len(parts) <= pid_idx or not parts[pid_idx].isdigit():
            continue
        pid = int(parts[pid_idx])
        ppid = int(parts[ppid_idx]) if ppid_idx is not None and len(parts) > ppid_idx and parts[ppid_idx].isdigit() else None
        name = parts[name_idx] if name_idx is not None and len(parts) > name_idx else parts[-1]
        rows.append((pid, ppid, name))
    return rows

# ─── Real Memory Reader via /proc/[pid]/statm ────────────────────────────────

def get_proc_memory_mb(pid_str):
    """Read real RSS memory in MB from /proc/[pid]/statm (works on Android non-root)."""
    try:
        page_size = os.sysconf('SC_PAGE_SIZE') if hasattr(os, 'sysconf') else 4096
        with open(f'/proc/{pid_str}/statm', 'r') as f:
            parts = f.read().split()
            if len(parts) >= 2:
                pages = int(parts[1])
                return round((pages * page_size) / (1024.0 * 1024.0), 1)
    except Exception:
        pass
    return 0.0

def get_real_processes():
    """Enumerate live processes & Android apps using dumpsys meminfo, activity recents/processes, ps -A, and /proc."""
    processes = []
    seen_pids = set()
    seen_names = set()
    self_pid = os.getpid()

    # 1. Android dumpsys meminfo parser (Extracts ALL active Android apps: com.whatsapp, com.android.chrome, system_server)
    try:
        res = subprocess.run(['dumpsys', 'meminfo'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=4)
        if res.returncode == 0 and res.stdout:
            # Pattern 1:  245,120 kB: com.whatsapp (pid 14502)
            pattern1 = re.compile(r'([\d,]+)\s*kB:\s*([^\s()]+)\s*\(pid\s*(\d+)', re.IGNORECASE)
            # Pattern 2: 12345: com.android.chrome (pid 12345 / activities)
            pattern2 = re.compile(r'pid\s*(\d+)\s*[:/]\s*([a-zA-Z0-9_.]+)', re.IGNORECASE)

            for line in res.stdout.split('\n'):
                match = pattern1.search(line)
                if match:
                    kb_str, pkg_name, pid_str = match.groups()
                    pid = int(pid_str)
                    kb = int(kb_str.replace(',', ''))
                    mb = round(kb / 1024.0, 1)

                    if pkg_name in ('ps', 'top', 'sh', 'cat', 'stty', 'zombie'):
                        continue

                    if pid not in seen_pids:
                        seen_pids.add(pid)
                        seen_names.add(pkg_name)
                        processes.append({
                            "pid": pid,
                            "parentPid": None,
                            "name": pkg_name,
                            "executablePath": f"/data/app/{pkg_name}" if pkg_name.startswith("com.") else f"/system/bin/{pkg_name}",
                            "cpuPct": 0.0,
                            "memoryMb": mb,
                            "sha256Hash": "ANDROID_PACKAGE"
                        })
                else:
                    match2 = pattern2.search(line)
                    if match2:
                        pid_str, pkg_name = match2.groups()
                        pid = int(pid_str)
                        if pkg_name.startswith("com.") and pid not in seen_pids:
                            seen_pids.add(pid)
                            seen_names.add(pkg_name)
                            mb = get_proc_memory_mb(pid_str)
                            processes.append({
                                "pid": pid,
                                "parentPid": None,
                                "name": pkg_name,
                                "executablePath": f"/data/app/{pkg_name}",
                                "cpuPct": 0.0,
                                "memoryMb": mb,
                                "sha256Hash": "ANDROID_PACKAGE"
                            })
    except Exception:
        pass

    # 2. Android dumpsys activity recents / processes parser
    try:
        res = subprocess.run(['dumpsys', 'activity', 'processes'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=3)
        if res.returncode == 0 and res.stdout:
            # Pattern: ProcessRecord{hash pid:package/uid}
            pattern = re.compile(r'ProcessRecord\{[^\}]+\s+(\d+):([a-zA-Z0-9_.]+)/', re.IGNORECASE)
            for line in res.stdout.split('\n'):
                m = pattern.search(line)
                if m:
                    pid_str, pkg_name = m.groups()
                    pid = int(pid_str)
                    if pid not in seen_pids:
                        seen_pids.add(pid)
                        seen_names.add(pkg_name)
                        mb = get_proc_memory_mb(pid_str)
                        processes.append({
                            "pid": pid,
                            "parentPid": None,
                            "name": pkg_name,
                            "executablePath": f"/data/app/{pkg_name}" if pkg_name.startswith("com.") else f"/system/bin/{pkg_name}",
                            "cpuPct": 0.0,
                            "memoryMb": mb,
                            "sha256Hash": "ANDROID_PACKAGE"
                        })
    except Exception:
        pass

    # 3. System `ps` parsers. Android toybox variants expose system/app
    # processes even when /proc/[pid]/cmdline is hidden from Termux. Try explicit
    # columns first, then fall back to the device default header.
    for ps_cmd in (
        ['ps', '-A', '-o', 'PID,PPID,NAME,ARGS'],
        ['ps', '-e', '-o', 'PID,PPID,NAME,ARGS'],
        ['ps', '-A'],
        ['ps'],
    ):
        try:
            res = subprocess.run(ps_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=3)
            if res.returncode == 0 and res.stdout:
                for pid, ppid, name in _parse_ps_table(res.stdout):
                    if pid != self_pid:
                        exe = name if '/' in name else f"/system/bin/{os.path.basename(name)}"
                        _add_process(processes, seen_pids, seen_names, pid, os.path.basename(name), exe, ppid)
        except Exception:
            continue

    # 4. Enumerate /proc/[pid] reading /proc/[pid]/comm for local Linux/Termux processes
    try:
        if os.path.exists('/proc'):
            all_pids = [p for p in os.listdir('/proc') if p.isdigit()]

            for pid_str in all_pids:
                pid = int(pid_str)
                if pid in seen_pids or pid == self_pid:
                    continue
                proc_dir = f'/proc/{pid_str}'
                name = ''
                exe_path = ''

                try:
                    with open(f'{proc_dir}/comm', 'r') as f:
                        name = f.read().strip()
                except Exception:
                    pass

                try:
                    with open(f'{proc_dir}/cmdline', 'rb') as f:
                        content = f.read(512).replace(b'\x00', b' ').decode('utf-8', errors='ignore').strip()
                        if content:
                            cmd_parts = content.split()
                            exe_path = cmd_parts[0]
                            cmd_name = os.path.basename(cmd_parts[0])
                            if cmd_name and not name:
                                name = cmd_name
                except Exception:
                    pass

                if name in ('ps', 'sh', 'cat', 'stty', '-b', 'zombie') or name.startswith('pid-'):
                    continue

                if name == 'python' and 'python' in seen_names:
                    continue

                if not exe_path:
                    try:
                        exe_path = os.readlink(f'{proc_dir}/exe')
                    except Exception:
                        exe_path = f'/proc/{pid_str}/exe'

                memory_mb = get_proc_memory_mb(pid_str)
                seen_pids.add(pid)
                seen_names.add(name)

                processes.append({
                    "pid": pid,
                    "parentPid": None,
                    "name": name,
                    "executablePath": exe_path,
                    "cpuPct": 0.0,
                    "memoryMb": memory_mb,
                    "sha256Hash": compute_sha256(exe_path) if memory_mb > 0 else "SYSTEM_PROTECTED"
                })
    except Exception:
        pass

    # Sort processes by Memory MB (descending)
    processes.sort(key=lambda p: (p['memoryMb'], p['pid']), reverse=True)
    return processes[:100], len(processes)


# ─── Network Sockets from /proc/net/{tcp,tcp6,udp,udp6} ─────────────────────

def _decode_hex_ip_port(hex_str):
    """Decode kernel hex IP:PORT from /proc/net/{tcp,tcp6}. Handles IPv4 & IPv6 format."""
    try:
        ip_hex, port_hex = hex_str.split(':')
        port = int(port_hex, 16)
        
        # IPv4 (8 hex chars, little endian)
        if len(ip_hex) == 8:
            ip_int = int(ip_hex, 16)
            ip_bytes = struct.pack('<I', ip_int)
            return '.'.join(str(b) for b in ip_bytes), port
            
        # IPv6 (32 hex chars)
        elif len(ip_hex) == 32:
            raw_bytes = bytearray()
            for i in range(0, 32, 8):
                part = int(ip_hex[i:i+8], 16)
                raw_bytes.extend(struct.pack('<I', part))
                
            # IPv4-mapped IPv6 (::ffff:w.x.y.z)
            if raw_bytes[:12] == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff':
                return '.'.join(str(b) for b in raw_bytes[12:16]), port
                
            # Regular IPv6
            words = [f"{raw_bytes[i]<<8 | raw_bytes[i+1]:x}" for i in range(0, 16, 2)]
            ip_str = ':'.join(words)
            if ip_str == '0:0:0:0:0:0:0:0':
                ip_str = '0.0.0.0'
            return ip_str, port
    except Exception:
        pass
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
    uid_map = get_uid_package_map()

    try:
        if not os.path.exists(filepath):
            return sockets
            
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
            uid = int(parts[7]) if len(parts) > 7 else 0
            inode = parts[9] if len(parts) > 9 else '0'

            # Skip loopback-only connections
            if (local_ip in ('127.0.0.1', '0.0.0.0', '::1') and remote_ip in ('127.0.0.1', '0.0.0.0', '::1') and state != 'LISTEN'):
                continue

            # Resolve process name from UID map (e.g. com.whatsapp, com.android.chrome)
            proc_name = uid_map.get(uid, f"uid-{uid}")

            sockets.append({
                "pid": 0,  # Resolved via /proc/[pid]/fd below if possible
                "processName": proc_name,
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
            resolved = pid_name.get(pid)
            if resolved:
                sock['processName'] = resolved
        sock.pop('inode', None)



def _append_socket(sockets, seen_keys, protocol, local_ip, local_port, remote_ip, remote_port, status, process_name='unknown', pid=0):
    try:
        local_port = int(local_port)
        remote_port = int(remote_port)
    except Exception:
        return
    if local_ip in ('127.0.0.1', '::1') and remote_ip in ('127.0.0.1', '::1', '0.0.0.0', '*') and status != 'LISTEN':
        return
    key = (protocol, local_ip, local_port, remote_ip, remote_port, status, pid or 0)
    if key in seen_keys:
        return
    seen_keys.add(key)
    sockets.append({
        "pid": pid or 0,
        "processName": process_name or 'unknown',
        "protocol": protocol,
        "localAddress": local_ip,
        "localPort": local_port,
        "remoteAddress": remote_ip,
        "remotePort": remote_port,
        "status": status
    })

def _split_addr_port(value):
    value = value.strip()
    if value in ('*', '*:*'):
        return '0.0.0.0', 0
    if value.startswith('[') and ']:' in value:
        host, port = value.rsplit(']:', 1)
        return host[1:], int(port) if port.isdigit() else 0
    if ':' in value:
        host, port = value.rsplit(':', 1)
        if port == '*':
            port = '0'
        return host or '0.0.0.0', int(port) if port.isdigit() else 0
    return value, 0

def _read_command_sockets():
    """Collect sockets via Android toybox ss/netstat when /proc/net is scoped."""
    sockets = []
    seen = set()
    commands = (
        ['ss', '-H', '-tunap'],
        ['ss', '-H', '-tunp'],
        ['netstat', '-tunp'],
        ['netstat', '-tun'],
    )
    for cmd in commands:
        try:
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=4)
            if res.returncode != 0 or not res.stdout:
                continue
            for line in res.stdout.splitlines():
                parts = line.split()
                if len(parts) < 5 or parts[0].lower().startswith(('proto', 'netid')):
                    continue
                proto_token = parts[0].upper()
                protocol = 'UDP' if 'UDP' in proto_token else 'TCP' if 'TCP' in proto_token else proto_token
                status = 'UNKNOWN'
                if protocol.startswith('TCP') and parts[1].upper() not in ('0', 'LISTEN'):
                    status = parts[1].upper().replace('-', '_')
                elif protocol.startswith('UDP'):
                    status = 'UDP'
                # ss: Netid State Recv-Q Send-Q Local Peer Process
                # netstat: Proto Recv-Q Send-Q Local Foreign State PID/Program
                local_idx = 4 if cmd[0] == 'ss' else 3
                peer_idx = 5 if cmd[0] == 'ss' else 4
                if len(parts) <= peer_idx:
                    continue
                if cmd[0] == 'netstat' and protocol.startswith('TCP') and len(parts) > 5:
                    status = parts[5].upper()
                local_ip, local_port = _split_addr_port(parts[local_idx])
                remote_ip, remote_port = _split_addr_port(parts[peer_idx])
                proc = 'unknown'
                pid = 0
                tail = ' '.join(parts[peer_idx + 1:])
                m = re.search(r'pid=(\d+),[^)]*?"([^"]+)"', tail)
                if m:
                    pid = int(m.group(1)); proc = m.group(2)
                else:
                    m = re.search(r'(\d+)/([^\s]+)', tail)
                    if m:
                        pid = int(m.group(1)); proc = m.group(2)
                _append_socket(sockets, seen, protocol, local_ip, local_port, remote_ip, remote_port, status, proc, pid)
        except Exception:
            continue
    return sockets

def get_real_sockets():
    """Read network sockets using ss/netstat plus /proc/net fallbacks."""
    all_sockets = _read_command_sockets()
    seen = {
        (s.get('protocol'), s.get('localAddress'), s.get('localPort'), s.get('remoteAddress'), s.get('remotePort'), s.get('status'), s.get('pid', 0))
        for s in all_sockets
    }

    proc_sockets = []
    for fname, proto in [('/proc/net/tcp', 'TCP'), ('/proc/net/tcp6', 'TCP6'),
                         ('/proc/net/udp', 'UDP'), ('/proc/net/udp6', 'UDP6')]:
        proc_sockets.extend(_read_proc_net_file(fname, proto))

    # Resolve PIDs where permissions allow
    _resolve_socket_pids(proc_sockets)
    for sock in proc_sockets:
        _append_socket(all_sockets, seen, sock.get('protocol'), sock.get('localAddress'), sock.get('localPort'),
                       sock.get('remoteAddress'), sock.get('remotePort'), sock.get('status'),
                       sock.get('processName'), sock.get('pid', 0))

    # Sort sockets: ESTABLISHED first, then LISTEN, UDP, then others
    priority = {'ESTABLISHED': 0, 'SYN_SENT': 1, 'LISTEN': 2, 'UDP': 3}
    all_sockets.sort(key=lambda s: priority.get(s['status'], 5))
    return all_sockets[:120]



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


# ─── Unique Persistent Device Identity Harvester ──────────────────────────

def get_persistent_device_identity():
    """Generate or load a unique persistent device identity per Android device."""
    config_path = os.path.expanduser('~/.guardian_device_id.json')
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                data = json.load(f)
                if data.get('agentId') and data.get('hostname'):
                    return data['agentId'], data['hostname']
        except Exception:
            pass

    brand = ""
    model = ""

    try:
        res = subprocess.run(['getprop', 'ro.product.brand'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2)
        if res.returncode == 0 and res.stdout.strip():
            brand = res.stdout.strip().capitalize()
    except Exception:
        pass

    try:
        res = subprocess.run(['getprop', 'ro.product.model'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2)
        if res.returncode == 0 and res.stdout.strip():
            model = res.stdout.strip()
    except Exception:
        pass

    if not brand or not model:
        try:
            if os.path.exists('/system/build.prop'):
                with open('/system/build.prop', 'r') as f:
                    for line in f:
                        if line.startswith('ro.product.brand=') and not brand:
                            brand = line.split('=')[1].strip().capitalize()
                        elif line.startswith('ro.product.model=') and not model:
                            model = line.split('=')[1].strip()
        except Exception:
            pass

    if not brand:
        brand = "Android"
    if not model:
        raw_host = socket.gethostname() or "Device"
        model = raw_host.replace("localhost", "Device")

    clean_brand = re.sub(r'[^a-zA-Z0-9]', '', brand)
    clean_model = re.sub(r'[^a-zA-Z0-9]', '-', model).strip('-')

    mac = get_real_mac_address()
    ip = get_primary_ip()
    seed = f"{mac}-{ip}-{platform.machine()}-{time.time()}"
    suffix = hashlib.md5(seed.encode()).hexdigest()[:4].upper()

    hostname = f"Android-{clean_brand}-{clean_model}-{suffix}"
    agent_id = f"agent-{hostname.lower()}"

    try:
        with open(config_path, 'w') as f:
            json.dump({'agentId': agent_id, 'hostname': hostname}, f)
    except Exception:
        pass

    return agent_id, hostname


# ─── System Inventory ───────────────────────────────────────────────────────

def get_system_inventory():
    agent_id, hostname = get_persistent_device_identity()
    _, total_mem_mb = get_real_ram_usage()

    android_ver = ""
    try:
        res = subprocess.run(['getprop', 'ro.build.version.release'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2)
        if res.returncode == 0 and res.stdout.strip():
            android_ver = res.stdout.strip()
    except Exception:
        pass

    if not android_ver:
        try:
            with open('/system/build.prop', 'r') as f:
                for line in f:
                    if 'ro.build.version.release' in line:
                        android_ver = line.split('=')[1].strip()
                        break
        except Exception:
            pass

    os_name = f"Android {android_ver}" if android_ver else f"Android ({platform.system()})"

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
        "hostname": hostname,
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
        elif not os.path.exists('/sys/fs/selinux') and os.path.exists('/system/build.prop'):
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
    home_dirs = ['/root', os.path.expanduser('~')] + glob.glob('/home/*')
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
    suspicious_libs = ['frida', 'xposed', 'substrate', 'inject', 'cydia']
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

def detect_promiscuous_interfaces():
    """Detect network interfaces operating in promiscuous mode (packet sniffing / tcpdump)."""
    findings = []
    try:
        for flags_path in glob.glob('/sys/class/net/*/flags'):
            try:
                iface = flags_path.split('/')[-2]
                if iface == 'lo':
                    continue
                with open(flags_path, 'r') as f:
                    flags_hex = int(f.read().strip(), 16)
                # IFF_PROMISC = 0x100
                if flags_hex & 0x100:
                    findings.append({
                        "findingType": "PROMISCUOUS_MODE",
                        "severity": "CRITICAL",
                        "description": f"Interface de rede '{iface}' em modo promíscuo (captura de pacotes ativa)",
                        "evidence": f"Flags Hex: {hex(flags_hex)} em {flags_path}",
                        "mitreId": "T1040"
                    })
            except Exception:
                continue
    except Exception:
        pass
    return findings

def detect_global_process_tracers():
    """Scan all running processes for attached debuggers (TracerPid > 0)."""
    findings = []
    try:
        for status_path in glob.glob('/proc/[0-9]*/status'):
            try:
                pid = status_path.split('/')[2]
                with open(status_path, 'r') as f:
                    proc_name = "unknown"
                    tracer_pid = 0
                    for line in f:
                        if line.startswith('Name:'):
                            proc_name = line.split(':')[1].strip()
                        elif line.startswith('TracerPid:'):
                            tracer_pid = int(line.split(':')[1].strip())
                    if tracer_pid > 0 and pid != str(os.getpid()):
                        findings.append({
                            "findingType": "PROCESS_TRACED",
                            "severity": "CRITICAL",
                            "description": f"Processo '{proc_name}' (PID {pid}) está sendo depurado/interceptado por PID {tracer_pid}",
                            "evidence": f"TracerPid: {tracer_pid} em {status_path}",
                            "mitreId": "T1622"
                        })
            except Exception:
                continue
    except Exception:
        pass
    return findings

def detect_unlinked_memory_executables():
    """Scan memory maps for unlinked binaries or RWX anonymous executable pages."""
    findings = []
    try:
        for maps_path in glob.glob('/proc/[0-9]*/maps'):
            try:
                pid = maps_path.split('/')[2]
                with open(maps_path, 'r') as f:
                    for line in f:
                        if 'rwxp' in line or '(deleted)' in line:
                            if any(ext in line for ext in ['.so', '.bin', '.elf', '.sh']):
                                findings.append({
                                    "findingType": "UNLINKED_EXECUTION",
                                    "severity": "HIGH",
                                    "description": f"Execução de memória não-vinculada ou página RWX no PID {pid}",
                                    "evidence": line.strip()[:100],
                                    "mitreId": "T1055"
                                })
                                break
            except Exception:
                continue
    except Exception:
        pass
    return findings

def detect_running_vpn():
    """Detect if a VPN connection is active (tun0/ppp0 interfaces)."""
    findings = []
    try:
        for iface in ['tun0', 'tun1', 'ppp0', 'ppp1']:
            if os.path.exists(f'/sys/class/net/{iface}'):
                findings.append({
                    'findingType': 'VPN_ACTIVE',
                    'severity': 'INFO',
                    'description': f'Interface VPN ativa detectada: {iface}',
                    'evidence': f'/sys/class/net/{iface} exists',
                    'mitreId': 'T1572'
                })
    except Exception:
        pass
    return findings


def detect_open_listening_ports():
    """Detect all listening ports and flag dangerous ones."""
    findings = []
    dangerous_ports = {21: 'FTP', 23: 'Telnet', 25: 'SMTP', 445: 'SMB', 3389: 'RDP', 5555: 'ADB', 8080: 'HTTP-Proxy', 4444: 'Metasploit', 1337: 'Hacker', 6667: 'IRC-C2'}
    try:
        for proto_file in ['/proc/net/tcp', '/proc/net/tcp6']:
            if not os.path.exists(proto_file):
                continue
            with open(proto_file, 'r') as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 4 and parts[3] == '0A':  # LISTEN state
                        port_hex = parts[1].split(':')[1]
                        port = int(port_hex, 16)
                        if port in dangerous_ports:
                            findings.append({
                                'findingType': 'DANGEROUS_LISTENING_PORT',
                                'severity': 'HIGH' if port in (4444, 1337, 6667, 5555) else 'WARNING',
                                'description': f'Porta perigosa {port} ({dangerous_ports[port]}) em LISTEN',
                                'evidence': f'Protocolo: {proto_file}, Porta: {port}',
                                'mitreId': 'T1071'
                            })
    except Exception:
        pass
    return findings


def detect_world_writable_executables():
    """Detect world-writable executables in critical directories."""
    findings = []
    try:
        critical_dirs = ['/system/bin', '/system/xbin', '/vendor/bin', '/data/local/tmp']
        for d in critical_dirs:
            if not os.path.isdir(d):
                continue
            try:
                for f in os.listdir(d)[:50]:
                    fpath = os.path.join(d, f)
                    try:
                        mode = os.stat(fpath).st_mode
                        if mode & 0o002:  # world-writable
                            findings.append({
                                'findingType': 'WORLD_WRITABLE_EXEC',
                                'severity': 'HIGH',
                                'description': f'Executável com permissão de escrita global: {fpath}',
                                'evidence': f'Mode: {oct(mode)}',
                                'mitreId': 'T1222'
                            })
                    except Exception:
                        continue
            except PermissionError:
                continue
    except Exception:
        pass
    return findings


def detect_battery_and_device_info():
    """Collect device battery and temperature as telemetry info findings."""
    findings = []
    try:
        bat_path = '/sys/class/power_supply/battery'
        if os.path.exists(bat_path):
            level = ''
            status = ''
            temp = ''
            try:
                with open(f'{bat_path}/capacity', 'r') as f:
                    level = f.read().strip()
            except Exception:
                pass
            try:
                with open(f'{bat_path}/status', 'r') as f:
                    status = f.read().strip()
            except Exception:
                pass
            try:
                with open(f'{bat_path}/temp', 'r') as f:
                    raw = f.read().strip()
                    temp = f"{int(raw) / 10.0}°C"
            except Exception:
                pass
            if level and int(level) < 15:
                findings.append({
                    'findingType': 'LOW_BATTERY',
                    'severity': 'WARNING',
                    'description': f'Bateria baixa: {level}% ({status})',
                    'evidence': f'Nível: {level}%, Status: {status}, Temp: {temp}',
                    'mitreId': 'N/A'
                })
            findings.append({
                'findingType': 'DEVICE_BATTERY_STATUS',
                'severity': 'INFO',
                'description': f'Bateria: {level}% | Status: {status} | Temp: {temp}',
                'evidence': f'{bat_path}',
                'mitreId': 'N/A'
                })
    except Exception:
        pass
    return findings


def detect_developer_options():
    """Detect if Android developer options and USB debugging are enabled."""
    findings = []
    try:
        checks = [
            ('adb_enabled', 'USB Debugging (ADB) está HABILITADO'),
            ('development_settings_enabled', 'Opções de Desenvolvedor estão HABILITADAS'),
            ('install_non_market_apps', 'Instalação de fontes desconhecidas HABILITADA'),
        ]
        for prop, desc in checks:
            try:
                res = subprocess.run(['settings', 'get', 'global', prop], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2)
                if res.returncode == 0 and res.stdout.strip() == '1':
                    findings.append({
                        'findingType': 'DEV_OPTIONS_ENABLED',
                        'severity': 'WARNING' if 'ADB' in desc else 'INFO',
                        'description': desc,
                        'evidence': f'{prop} = 1',
                        'mitreId': 'T1456'
                    })
            except Exception:
                continue
    except Exception:
        pass
    return findings


def detect_screen_lock_status():
    """Check if screen lock is configured."""
    findings = []
    try:
        res = subprocess.run(['settings', 'get', 'secure', 'lockscreen.password_type'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2)
        if res.returncode == 0:
            val = res.stdout.strip()
            if val in ('0', '65536', 'null', ''):
                findings.append({
                    'findingType': 'NO_SCREEN_LOCK',
                    'severity': 'HIGH',
                    'description': 'Dispositivo NÃO possui bloqueio de tela configurado!',
                    'evidence': f'lockscreen.password_type = {val}',
                    'mitreId': 'T1461'
                })
    except Exception:
        pass
    return findings


def detect_installed_security_apps():
    """Check for known security/antivirus apps installed."""
    findings = []
    security_apps = {
        'com.lookout': 'Lookout Security',
        'com.avast.android.mobilesecurity': 'Avast Antivirus',
        'com.bitdefender.security': 'Bitdefender',
        'com.kaspersky.security.cloud': 'Kaspersky',
        'org.malwarebytes.antimalware': 'Malwarebytes',
        'com.eset.ems2.gp': 'ESET Mobile Security',
        'com.norton.engine': 'Norton Mobile',
        'com.sophos.smsec': 'Sophos Mobile',
    }
    found = []
    try:
        res = subprocess.run(['pm', 'list', 'packages'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
        if res.returncode == 0:
            pkgs = res.stdout
            for pkg, name in security_apps.items():
                if pkg in pkgs:
                    found.append(name)
    except Exception:
        pass

    if found:
        findings.append({
            'findingType': 'SECURITY_APP_INSTALLED',
            'severity': 'INFO',
            'description': f'Apps de segurança instalados: {", ".join(found)}',
            'evidence': ', '.join(found),
            'mitreId': 'N/A'
        })
    else:
        findings.append({
            'findingType': 'NO_SECURITY_APP',
            'severity': 'WARNING',
            'description': 'Nenhum aplicativo de segurança/antivírus detectado no dispositivo',
            'evidence': 'pm list packages não contém nenhum pacote de segurança conhecido',
            'mitreId': 'T1629.003'
        })
    return findings


def detect_active_wifi_info():
    """Detect current Wi-Fi connection details."""
    findings = []
    try:
        res = subprocess.run(['dumpsys', 'wifi'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=3)
        if res.returncode == 0 and res.stdout:
            ssid = ''
            bssid = ''
            freq = ''
            for line in res.stdout.split('\n'):
                l = line.strip()
                if 'mWifiInfo' in l or 'SSID:' in l:
                    m = re.search(r'SSID:\s*"?([^"\s,]+)', l)
                    if m:
                        ssid = m.group(1)
                if 'BSSID:' in l:
                    m = re.search(r'BSSID:\s*([0-9a-f:]+)', l, re.IGNORECASE)
                    if m:
                        bssid = m.group(1)
                if 'Frequency:' in l:
                    m = re.search(r'Frequency:\s*(\d+)', l)
                    if m:
                        freq = f"{m.group(1)}MHz"
            if ssid:
                findings.append({
                    'findingType': 'WIFI_CONNECTION',
                    'severity': 'INFO',
                    'description': f'Conectado ao Wi-Fi: {ssid} ({bssid}) @ {freq}',
                    'evidence': f'SSID={ssid}, BSSID={bssid}, Freq={freq}',
                    'mitreId': 'N/A'
                })
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
    all_findings.extend(detect_promiscuous_interfaces())
    all_findings.extend(detect_global_process_tracers())
    all_findings.extend(detect_unlinked_memory_executables())
    all_findings.extend(detect_running_vpn())
    all_findings.extend(detect_open_listening_ports())
    all_findings.extend(detect_world_writable_executables())
    all_findings.extend(detect_battery_and_device_info())
    all_findings.extend(detect_developer_options())
    all_findings.extend(detect_screen_lock_status())
    all_findings.extend(detect_installed_security_apps())
    all_findings.extend(detect_active_wifi_info())
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

def kill_old_agent_processes():
    """Kill old running python agent.py background processes so duplicates don't accumulate."""
    my_pid = os.getpid()
    try:
        if os.path.exists('/proc'):
            for p in os.listdir('/proc'):
                if p.isdigit():
                    pid = int(p)
                    if pid != my_pid:
                        try:
                            with open(f'/proc/{p}/cmdline', 'rb') as f:
                                cmd = f.read().decode('utf-8', errors='ignore')
                                if 'agent.py' in cmd or 'guardian_termux' in cmd:
                                    os.kill(pid, 9)
                        except Exception:
                            pass
    except Exception:
        pass

def main():
    kill_old_agent_processes()
    config_dir = os.path.expanduser("~/.guardian")
    os.makedirs(config_dir, exist_ok=True)
    config_file = os.path.join(config_dir, "server_url.txt")

    server_ip = None

    # 1. Argumento da linha de comando
    if len(sys.argv) > 1 and sys.argv[1].strip():
        server_ip = sys.argv[1].strip()
        try:
            with open(config_file, "w") as f:
                f.write(server_ip)
        except Exception:
            pass

    # 2. Variável de ambiente
    if not server_ip and os.environ.get("GUARDIAN_SERVER"):
        server_ip = os.environ.get("GUARDIAN_SERVER").strip()

    # 3. Arquivo de configuração persistente
    if not server_ip and os.path.exists(config_file):
        try:
            with open(config_file, "r") as f:
                server_ip = f.read().strip()
        except Exception:
            pass

    # 4. Prompt interativo se stdin for um terminal real
    if not server_ip and sys.stdin.isatty():
        try:
            server_ip = input("Digite o IP da maquina mestre (ex: 192.168.50.140): ").strip()
            if server_ip:
                try:
                    with open(config_file, "w") as f:
                        f.write(server_ip)
                except Exception:
                    pass
        except Exception:
            pass

    # Fallback se nenhum IP for fornecido
    if not server_ip:
        server_ip = "192.168.50.140"

    if not server_ip.startswith("http"):
        server_url = f"http://{server_ip}:4000"
    else:
        server_url = server_ip

    print(f"╔════════════════════════════════════════════════════════╗")
    print(f"║  Guardian EDR Agent v12.0 - Android/Linux Deep Probe ║")
    print(f"╠════════════════════════════════════════════════════════╣")
    print(f"║  Servidor Mestre: {server_url:<37s}║")
    print(f"╚════════════════════════════════════════════════════════╝")

    agent_id, hostname = get_persistent_device_identity()
    inventory = get_system_inventory()


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

        time.sleep(20)

if __name__ == "__main__":
    main()
