"""
log_analyzer.py — Honeypot Log Analysis & Result Processing
Parses honeypot JSON logs and optional pcap captures to identify attack
patterns and produce summary tables, charts, and a findings report.

Usage:
    python3 log_analyzer.py --log honeypot.log (Use this command)
    (if it doesn't work) -> py log_analyzer.py --log honeypot.log
    (if it doesn't work) -> python3 log_analyzer.py --log honeypot.log
    
    python3 log_analyzer.py --log honeypot.log --pcap capture.pcap
    python3 log_analyzer.py --log honeypot.log --pcap capture.pcap --output results/

Requirements:
    pip install matplotlib scapy 
    (if it doesn't work) -> python -m pip install matplotlib scapy 
    (if it doesn't work) -> py -m pip install matplotlib scapy

"""

import json
import os
import argparse
from datetime import datetime
from collections import Counter, defaultdict

import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for server/VM use
import matplotlib.pyplot as plt


# 1. LOG PARSING

def parse_logs(log_file: str) -> list[dict]:
    """Parse the honeypot JSON log file into a list of event dictionaries."""
    events = []
    with open(log_file, "r") as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                entry["_line"] = line_num
                events.append(entry)
            except json.JSONDecodeError:
                print(f"[!] Skipping malformed line {line_num}")
    return events


def split_by_event(events: list[dict]) -> dict[str, list[dict]]:
    """Split events into separate lists by event type."""
    grouped = defaultdict(list)
    for e in events:
        grouped[e.get("event", "unknown")].append(e)
    return grouped


# 2. IDENTIFICATION ANALYSIS


def analyze_login_attempts(logins: list[dict]) -> dict:
    """Analyze login attempts: repeated attempts, common credentials, brute-force detection."""
    if not logins:
        return {"total": 0}

    usernames = Counter(e["username"] for e in logins)
    passwords = Counter(e["password"] for e in logins)
    credentials = Counter((e["username"], e["password"]) for e in logins)
    by_ip = Counter(e["source_ip"] for e in logins)
    by_service = Counter(e["service"] for e in logins)

    # Brute-force detection: IPs with more than 10 login attempts
    brute_force_ips = {ip: count for ip, count in by_ip.items() if count >= 10}

    # Success rate
    successful = [e for e in logins if e.get("success")]

    return {
        "total": len(logins),
        "successful": len(successful),
        "failed": len(logins) - len(successful),
        "unique_usernames": len(usernames),
        "unique_passwords": len(passwords),
        "top_usernames": usernames.most_common(10),
        "top_passwords": passwords.most_common(10),
        "top_credentials": credentials.most_common(10),
        "attempts_by_ip": by_ip.most_common(),
        "attempts_by_service": by_service.most_common(),
        "brute_force_ips": brute_force_ips,
    }


def analyze_commands(commands: list[dict]) -> dict:
    """Analyze commands executed by attackers."""
    if not commands:
        return {"total": 0}

    all_cmds = Counter(e["command"] for e in commands)
    by_ip = defaultdict(list)
    by_service = Counter(e["service"] for e in commands)

    for e in commands:
        by_ip[e["source_ip"]].append(e["command"])

    # Classify commands by intent
    recon_keywords = ["whoami", "id", "uname", "hostname", "ifconfig", "ip addr",
                      "netstat", "ps", "ls", "pwd", "cat /etc", "w", "last", "history"]
    exfil_keywords = ["wget", "curl", "scp", "nc ", "ftp", "/dev/tcp"]
    escalation_keywords = ["sudo", "chmod", "chown", "su ", "passwd", "/etc/shadow",
                           "find / -perm", "SUID"]
    scan_keywords = ["GET /", "POST /", "nmap", "scan"]

    categories = {"reconnaissance": [], "exfiltration": [], "privilege_escalation": [],
                   "scanning": [], "other": []}

    for cmd, count in all_cmds.items():
        cmd_lower = cmd.lower()
        categorized = False
        if any(k in cmd_lower for k in exfil_keywords):
            categories["exfiltration"].append((cmd, count))
            categorized = True
        if any(k in cmd_lower for k in escalation_keywords):
            categories["privilege_escalation"].append((cmd, count))
            categorized = True
        if any(k in cmd_lower for k in recon_keywords):
            categories["reconnaissance"].append((cmd, count))
            categorized = True
        if any(k in cmd_lower for k in scan_keywords):
            categories["scanning"].append((cmd, count))
            categorized = True
        if not categorized:
            categories["other"].append((cmd, count))

    return {
        "total": len(commands),
        "unique_commands": len(all_cmds),
        "top_commands": all_cmds.most_common(15),
        "commands_by_ip": {ip: cmds for ip, cmds in by_ip.items()},
        "commands_by_service": by_service.most_common(),
        "categories": categories,
    }


def analyze_scan_patterns(connections: list[dict], disconnections: list[dict]) -> dict:
    """Detect port scanning patterns based on rapid connections with short durations."""
    if not connections:
        return {"total_connections": 0}

    conn_by_ip = defaultdict(list)
    for e in connections:
        conn_by_ip[e["source_ip"]].append(e)

    disc_durations = {}
    for e in disconnections:
        key = (e["source_ip"], e.get("session_id", ""))
        disc_durations[key] = e.get("duration_seconds", 0)

    scan_suspects = {}
    for ip, conns in conn_by_ip.items():
        if len(conns) < 3:
            continue

        # Sort by timestamp
        sorted_conns = sorted(conns, key=lambda x: x["timestamp"])
        timestamps = [datetime.strptime(c["timestamp"], "%Y-%m-%dT%H:%M:%SZ") for c in sorted_conns]

        # Calculate time intervals between connections
        intervals = []
        for i in range(1, len(timestamps)):
            diff = (timestamps[i] - timestamps[i - 1]).total_seconds()
            intervals.append(diff)

        avg_interval = sum(intervals) / len(intervals) if intervals else 999

        # Rapid connections (avg < 2 seconds) suggest port scanning
        if avg_interval < 2 and len(conns) >= 5:
            scan_suspects[ip] = {
                "connection_count": len(conns),
                "avg_interval_seconds": round(avg_interval, 3),
                "services_targeted": list(set(c["service"] for c in conns)),
                "first_seen": sorted_conns[0]["timestamp"],
                "last_seen": sorted_conns[-1]["timestamp"],
            }

    by_service = Counter(e["service"] for e in connections)

    return {
        "total_connections": len(connections),
        "unique_source_ips": len(conn_by_ip),
        "connections_by_service": by_service.most_common(),
        "connections_by_ip": {ip: len(conns) for ip, conns in conn_by_ip.items()},
        "scan_suspects": scan_suspects,
    }


def analyze_service_targeting(events: list[dict]) -> dict:
    """Analyze which services are being targeted most."""
    service_events = defaultdict(lambda: defaultdict(int))
    service_ips = defaultdict(set)

    for e in events:
        service = e.get("service", "unknown")
        event_type = e.get("event", "unknown")
        service_events[service][event_type] += 1
        if "source_ip" in e:
            service_ips[service].add(e["source_ip"])

    return {
        "services": {
            svc: {
                "events": dict(counts),
                "total_events": sum(counts.values()),
                "unique_attackers": len(service_ips.get(svc, set())),
            }
            for svc, counts in service_events.items()
        }
    }


# 3. PCAP CORRELATION


def correlate_pcap(pcap_file: str, events: list[dict]) -> dict:
    """Correlate packet capture data with honeypot logs."""
    try:
        from scapy.all import rdpcap, IP, TCP, UDP
    except ImportError:
        return {"error": "scapy not installed — run: pip install scapy"}

    packets = rdpcap(pcap_file)
    print(f"[*] Loaded {len(packets)} packets from {pcap_file}")

    # Extract packet info
    pcap_ips = Counter()
    pcap_ports = Counter()
    pcap_flags = Counter()
    syn_packets = []
    pcap_protocols = Counter()

    for pkt in packets:
        if IP in pkt:
            pcap_ips[pkt[IP].src] += 1
            pcap_protocols["IP"] += 1

            if TCP in pkt:
                pcap_ports[pkt[TCP].dport] += 1
                pcap_protocols["TCP"] += 1
                flags = str(pkt[TCP].flags)
                pcap_flags[flags] += 1
                if "S" in flags and "A" not in flags:
                    syn_packets.append({
                        "src_ip": pkt[IP].src,
                        "dst_port": pkt[TCP].dport,
                        "sport": pkt[TCP].sport,
                    })
            elif UDP in pkt:
                pcap_ports[pkt[UDP].dport] += 1
                pcap_protocols["UDP"] += 1

    # Correlate: match log source IPs with pcap source IPs
    log_ips = set(e.get("source_ip") for e in events if "source_ip" in e)
    pcap_ip_set = set(pcap_ips.keys())

    matched_ips = log_ips & pcap_ip_set
    log_only_ips = log_ips - pcap_ip_set
    pcap_only_ips = pcap_ip_set - log_ips

    # Port correlation
    log_services = Counter(e.get("service") for e in events if "service" in e)
    service_to_ports = {"SSH": [22, 2222], "HTTP": [80, 8080]}

    port_correlation = {}
    for service, ports in service_to_ports.items():
        log_count = log_services.get(service, 0)
        pcap_count = sum(pcap_ports.get(p, 0) for p in ports)
        port_correlation[service] = {
            "log_events": log_count,
            "pcap_packets": pcap_count,
            "ports_checked": ports,
        }

    return {
        "pcap_total_packets": len(packets),
        "pcap_unique_ips": len(pcap_ip_set),
        "pcap_top_source_ips": pcap_ips.most_common(10),
        "pcap_top_dst_ports": pcap_ports.most_common(10),
        "pcap_tcp_flags": pcap_flags.most_common(),
        "pcap_protocols": pcap_protocols.most_common(),
        "syn_scan_packets": len(syn_packets),
        "correlation": {
            "matched_ips": list(matched_ips),
            "ips_in_logs_only": list(log_only_ips),
            "ips_in_pcap_only": list(pcap_only_ips),
            "match_rate": f"{len(matched_ips)}/{len(log_ips)}" if log_ips else "N/A",
        },
        "port_correlation": port_correlation,
    }


# 4. CHART GENERATION


def create_charts(login_analysis: dict, command_analysis: dict,
                  scan_analysis: dict, service_analysis: dict,
                  output_dir: str):
    """Generate summary charts as PNG files."""
    os.makedirs(output_dir, exist_ok=True)
    charts_created = []

    # ── Chart 1: Top Usernames ────────────────────────────────────────
    if login_analysis.get("top_usernames"):
        fig, ax = plt.subplots(figsize=(10, 5))
        names = [u[0] for u in login_analysis["top_usernames"]]
        counts = [u[1] for u in login_analysis["top_usernames"]]
        bars = ax.barh(names[::-1], counts[::-1], color="#2196F3")
        ax.set_xlabel("Number of Attempts")
        ax.set_title("Top 10 Usernames in Login Attempts")
        ax.bar_label(bars, padding=3)
        plt.tight_layout()
        path = os.path.join(output_dir, "chart_top_usernames.png")
        plt.savefig(path, dpi=150)
        plt.close()
        charts_created.append(path)

    # ── Chart 2: Top Passwords ────────────────────────────────────────
    if login_analysis.get("top_passwords"):
        fig, ax = plt.subplots(figsize=(10, 5))
        names = [p[0] for p in login_analysis["top_passwords"]]
        counts = [p[1] for p in login_analysis["top_passwords"]]
        bars = ax.barh(names[::-1], counts[::-1], color="#FF9800")
        ax.set_xlabel("Number of Attempts")
        ax.set_title("Top 10 Passwords in Login Attempts")
        ax.bar_label(bars, padding=3)
        plt.tight_layout()
        path = os.path.join(output_dir, "chart_top_passwords.png")
        plt.savefig(path, dpi=150)
        plt.close()
        charts_created.append(path)

    # ── Chart 3: Login Attempts by IP ─────────────────────────────────
    if login_analysis.get("attempts_by_ip"):
        fig, ax = plt.subplots(figsize=(10, 5))
        ips = [i[0] for i in login_analysis["attempts_by_ip"]]
        counts = [i[1] for i in login_analysis["attempts_by_ip"]]
        colors = ["#F44336" if login_analysis["brute_force_ips"].get(ip) else "#4CAF50" for ip in ips]
        bars = ax.barh(ips[::-1], counts[::-1], color=colors[::-1])
        ax.set_xlabel("Number of Login Attempts")
        ax.set_title("Login Attempts by Source IP (red = brute-force detected)")
        ax.bar_label(bars, padding=3)
        plt.tight_layout()
        path = os.path.join(output_dir, "chart_attempts_by_ip.png")
        plt.savefig(path, dpi=150)
        plt.close()
        charts_created.append(path)

    # ── Chart 4: Command Categories ───────────────────────────────────
    if command_analysis.get("categories"):
        cats = command_analysis["categories"]
        labels = []
        sizes = []
        for cat, cmds in cats.items():
            total = sum(c[1] for c in cmds)
            if total > 0:
                labels.append(cat.replace("_", " ").title())
                sizes.append(total)

        if sizes:
            fig, ax = plt.subplots(figsize=(8, 8))
            cat_colors = ["#2196F3", "#F44336", "#FF9800", "#9C27B0", "#607D8B"]
            ax.pie(sizes, labels=labels, autopct="%1.1f%%", startangle=90,
                   colors=cat_colors[:len(sizes)])
            ax.set_title("Attacker Command Categories")
            plt.tight_layout()
            path = os.path.join(output_dir, "chart_command_categories.png")
            plt.savefig(path, dpi=150)
            plt.close()
            charts_created.append(path)

    # ── Chart 5: Service Targeting ────────────────────────────────────
    if service_analysis.get("services"):
        fig, ax = plt.subplots(figsize=(8, 5))
        services = list(service_analysis["services"].keys())
        totals = [service_analysis["services"][s]["total_events"] for s in services]
        attackers = [service_analysis["services"][s]["unique_attackers"] for s in services]

        x = range(len(services))
        w = 0.35
        bars1 = ax.bar([i - w / 2 for i in x], totals, w, label="Total Events", color="#2196F3")
        bars2 = ax.bar([i + w / 2 for i in x], attackers, w, label="Unique Attackers", color="#F44336")
        ax.set_xticks(x)
        ax.set_xticklabels(services)
        ax.set_title("Service Targeting Overview")
        ax.set_ylabel("Count")
        ax.legend()
        ax.bar_label(bars1, padding=3)
        ax.bar_label(bars2, padding=3)
        plt.tight_layout()
        path = os.path.join(output_dir, "chart_service_targeting.png")
        plt.savefig(path, dpi=150)
        plt.close()
        charts_created.append(path)

    # ── Chart 6: Attack Timeline ──────────────────────────────────────
    if login_analysis.get("total", 0) > 0:
        # We need the raw events for this, but we can approximate from login data
        pass  # Timeline generated in create_timeline_chart

    return charts_created


def create_timeline_chart(events: list[dict], output_dir: str) -> str | None:
    """Generate a timeline of events over time."""
    timestamps = []
    for e in events:
        try:
            t = datetime.strptime(e["timestamp"], "%Y-%m-%dT%H:%M:%SZ")
            timestamps.append((t, e.get("event", "unknown")))
        except (ValueError, KeyError):
            continue

    if not timestamps:
        return None

    timestamps.sort(key=lambda x: x[0])

    # Group by minute
    minute_counts = defaultdict(lambda: defaultdict(int))
    for t, event_type in timestamps:
        minute_key = t.strftime("%H:%M")
        minute_counts[minute_key][event_type] += 1

    if not minute_counts:
        return None

    fig, ax = plt.subplots(figsize=(14, 5))
    minutes = sorted(minute_counts.keys())
    event_types = ["connection", "login_attempt", "command", "disconnection"]
    colors = {"connection": "#4CAF50", "login_attempt": "#F44336",
              "command": "#FF9800", "disconnection": "#607D8B"}

    bottom = [0] * len(minutes)
    for etype in event_types:
        values = [minute_counts[m].get(etype, 0) for m in minutes]
        ax.bar(minutes, values, bottom=bottom, label=etype,
               color=colors.get(etype, "#999999"), width=0.8)
        bottom = [b + v for b, v in zip(bottom, values)]

    ax.set_xlabel("Time (HH:MM)")
    ax.set_ylabel("Events")
    ax.set_title("Attack Timeline — Events Over Time")
    ax.legend()

    # Rotate x labels if there are many
    if len(minutes) > 20:
        plt.xticks(rotation=45, ha="right")
        # Show every nth label
        n = max(1, len(minutes) // 20)
        for i, label in enumerate(ax.xaxis.get_ticklabels()):
            if i % n != 0:
                label.set_visible(False)

    plt.tight_layout()
    path = os.path.join(output_dir, "chart_attack_timeline.png")
    plt.savefig(path, dpi=150)
    plt.close()
    return path


# 5. REPORT GENERATION


def generate_report(login_analysis: dict, command_analysis: dict,
                    scan_analysis: dict, service_analysis: dict,
                    pcap_analysis: dict | None, charts: list[str],
                    output_dir: str) -> str:
    """Generate a text-based findings report."""

    lines = []
    lines.append("=" * 70)
    lines.append("  HONEYPOT LOG ANALYSIS — ATTACK FINDINGS REPORT")
    lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 70)

    # ── Overview ──────────────────────────────────────────────────────
    lines.append("\n1. OVERVIEW")
    lines.append("-" * 40)
    total_events = (login_analysis.get("total", 0) +
                    command_analysis.get("total", 0) +
                    scan_analysis.get("total_connections", 0))
    lines.append(f"   Total events analyzed:        {total_events}")
    lines.append(f"   Total connections:            {scan_analysis.get('total_connections', 0)}")
    lines.append(f"   Total login attempts:         {login_analysis.get('total', 0)}")
    lines.append(f"   Total commands captured:      {command_analysis.get('total', 0)}")
    lines.append(f"   Unique source IPs:            {scan_analysis.get('unique_source_ips', 0)}")

    # ── Login Attempt Analysis ────────────────────────────────────────
    lines.append("\n2. LOGIN ATTEMPT ANALYSIS")
    lines.append("-" * 40)
    if login_analysis.get("total", 0) > 0:
        lines.append(f"   Failed attempts:              {login_analysis['failed']}")
        lines.append(f"   Successful attempts:          {login_analysis['successful']}")
        lines.append(f"   Unique usernames tried:       {login_analysis['unique_usernames']}")
        lines.append(f"   Unique passwords tried:       {login_analysis['unique_passwords']}")

        lines.append("\n   Top 10 Usernames:")
        for rank, (user, count) in enumerate(login_analysis["top_usernames"], 1):
            lines.append(f"     {rank:>2}. {user:<20} {count:>5} attempts")

        lines.append("\n   Top 10 Passwords:")
        for rank, (pwd, count) in enumerate(login_analysis["top_passwords"], 1):
            lines.append(f"     {rank:>2}. {pwd:<20} {count:>5} attempts")

        lines.append("\n   Top 10 Credential Pairs:")
        for rank, ((user, pwd), count) in enumerate(login_analysis["top_credentials"], 1):
            lines.append(f"     {rank:>2}. {user}:{pwd:<20} {count:>5} attempts")

        if login_analysis["brute_force_ips"]:
            lines.append("\n   [!] BRUTE-FORCE DETECTED (10+ attempts):")
            for ip, count in login_analysis["brute_force_ips"].items():
                lines.append(f"       {ip:<20} {count} attempts")
    else:
        lines.append("   No login attempts recorded.")

    # ── Command Analysis ──────────────────────────────────────────────
    lines.append("\n3. COMMAND ANALYSIS")
    lines.append("-" * 40)
    if command_analysis.get("total", 0) > 0:
        lines.append(f"   Total commands:               {command_analysis['total']}")
        lines.append(f"   Unique commands:              {command_analysis['unique_commands']}")

        lines.append("\n   Top 15 Commands:")
        for rank, (cmd, count) in enumerate(command_analysis["top_commands"], 1):
            lines.append(f"     {rank:>2}. {cmd:<50} {count:>3}x")

        lines.append("\n   Command Categories:")
        for cat, cmds in command_analysis["categories"].items():
            total = sum(c[1] for c in cmds)
            if total > 0:
                lines.append(f"     {cat.replace('_', ' ').title():<25} {total:>3} commands")
                for cmd, count in cmds[:5]:
                    lines.append(f"       - {cmd}")

        if command_analysis["categories"].get("exfiltration"):
            lines.append("\n   [!] EXFILTRATION COMMANDS DETECTED:")
            for cmd, count in command_analysis["categories"]["exfiltration"]:
                lines.append(f"       {cmd}")
    else:
        lines.append("   No commands recorded.")

    # ── Scan Pattern Analysis ─────────────────────────────────────────
    lines.append("\n4. SCAN PATTERN ANALYSIS")
    lines.append("-" * 40)
    if scan_analysis.get("scan_suspects"):
        lines.append("   [!] PORT SCANNING DETECTED:")
        for ip, info in scan_analysis["scan_suspects"].items():
            lines.append(f"       Source IP:          {ip}")
            lines.append(f"       Connections:        {info['connection_count']}")
            lines.append(f"       Avg interval:       {info['avg_interval_seconds']}s")
            lines.append(f"       Services targeted:  {', '.join(info['services_targeted'])}")
            lines.append(f"       First seen:         {info['first_seen']}")
            lines.append(f"       Last seen:          {info['last_seen']}")
            lines.append("")
    else:
        lines.append("   No obvious scan patterns detected.")

    lines.append("\n   Connections by Source IP:")
    for ip, count in sorted(scan_analysis.get("connections_by_ip", {}).items(),
                             key=lambda x: x[1], reverse=True):
        lines.append(f"     {ip:<20} {count:>5} connections")

    # ── Service Targeting ─────────────────────────────────────────────
    lines.append("\n5. SERVICE TARGETING")
    lines.append("-" * 40)
    for service, info in service_analysis.get("services", {}).items():
        lines.append(f"   {service}:")
        lines.append(f"     Total events:         {info['total_events']}")
        lines.append(f"     Unique attackers:      {info['unique_attackers']}")
        for event_type, count in info["events"].items():
            lines.append(f"     - {event_type:<20} {count:>5}")
        lines.append("")

    # ── PCAP Correlation ──────────────────────────────────────────────
    lines.append("\n6. LOG <-> PCAP CORRELATION")
    lines.append("-" * 40)
    if pcap_analysis and "error" not in pcap_analysis:
        lines.append(f"   Total packets in capture:     {pcap_analysis['pcap_total_packets']}")
        lines.append(f"   Unique IPs in capture:        {pcap_analysis['pcap_unique_ips']}")
        lines.append(f"   SYN packets (scan indicator): {pcap_analysis['syn_scan_packets']}")

        corr = pcap_analysis["correlation"]
        lines.append(f"\n   IP Correlation:")
        lines.append(f"     IPs in both logs & pcap:    {', '.join(corr['matched_ips']) or 'none'}")
        lines.append(f"     IPs in logs only:           {', '.join(corr['ips_in_logs_only']) or 'none'}")
        lines.append(f"     IPs in pcap only:           {', '.join(corr['ips_in_pcap_only']) or 'none'}")
        lines.append(f"     Match rate:                 {corr['match_rate']}")

        lines.append(f"\n   Port Correlation:")
        for service, info in pcap_analysis["port_correlation"].items():
            lines.append(f"     {service}: {info['log_events']} log events vs "
                         f"{info['pcap_packets']} packets (ports {info['ports_checked']})")

        lines.append(f"\n   Top Source IPs in PCAP:")
        for ip, count in pcap_analysis["pcap_top_source_ips"]:
            lines.append(f"     {ip:<20} {count:>5} packets")

        lines.append(f"\n   TCP Flags Distribution:")
        for flag, count in pcap_analysis["pcap_tcp_flags"]:
            lines.append(f"     {flag:<10} {count:>5} packets")
    elif pcap_analysis and "error" in pcap_analysis:
        lines.append(f"   {pcap_analysis['error']}")
    else:
        lines.append("   No pcap file provided.")

    # ── Charts ────────────────────────────────────────────────────────
    lines.append("\n7. GENERATED CHARTS")
    lines.append("-" * 40)
    if charts:
        for chart in charts:
            lines.append(f"   - {chart}")
    else:
        lines.append("   No charts generated (insufficient data).")

    lines.append("\n" + "=" * 70)
    lines.append("  END OF REPORT")
    lines.append("=" * 70)

    report_text = "\n".join(lines)

    # Save report
    report_path = os.path.join(output_dir, "attack_findings_report.txt")
    with open(report_path, "w") as f:
        f.write(report_text)

    return report_path


# MAIN


def main():
    parser = argparse.ArgumentParser(description="Honeypot Log Analyzer")
    parser.add_argument("--log", required=True, help="Path to honeypot.log (JSON lines)")
    parser.add_argument("--pcap", default=None, help="Path to packet capture file (.pcap)")
    parser.add_argument("--output", default="results", help="Output directory for charts and report")
    args = parser.parse_args()

    output_dir = args.output
    os.makedirs(output_dir, exist_ok=True)

    # ── Parse logs ────────────────────────────────────────────────────
    print(f"[*] Parsing logs from: {args.log}")
    events = parse_logs(args.log)
    print(f"    Loaded {len(events)} events")

    grouped = split_by_event(events)
    print(f"    Event types: {', '.join(f'{k} ({len(v)})' for k, v in grouped.items())}")

    # ── Run analysis ──────────────────────────────────────────────────
    print("[*] Analyzing login attempts...")
    login_analysis = analyze_login_attempts(grouped.get("login_attempt", []))

    print("[*] Analyzing commands...")
    command_analysis = analyze_commands(grouped.get("command", []))

    print("[*] Analyzing scan patterns...")
    scan_analysis = analyze_scan_patterns(
        grouped.get("connection", []),
        grouped.get("disconnection", []),
    )

    print("[*] Analyzing service targeting...")
    service_analysis = analyze_service_targeting(events)

    # ── PCAP correlation ──────────────────────────────────────────────
    pcap_analysis = None
    if args.pcap:
        print(f"[*] Correlating with pcap: {args.pcap}")
        pcap_analysis = correlate_pcap(args.pcap, events)

    # ── Generate charts ───────────────────────────────────────────────
    print("[*] Generating charts...")
    charts = create_charts(login_analysis, command_analysis,
                           scan_analysis, service_analysis, output_dir)

    timeline_path = create_timeline_chart(events, output_dir)
    if timeline_path:
        charts.append(timeline_path)

    print(f"    Created {len(charts)} charts")

    # ── Generate report ───────────────────────────────────────────────
    print("[*] Generating findings report...")
    report_path = generate_report(
        login_analysis, command_analysis, scan_analysis,
        service_analysis, pcap_analysis, charts, output_dir,
    )
    print(f"\n[+] Report saved: {report_path}")
    print(f"[+] Charts saved in: {output_dir}/")
    print("[+] Done!")


if __name__ == "__main__":
    main()