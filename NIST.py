#!/usr/bin/env python3
import sys
import os
import json
import socket
import platform
import subprocess
from datetime import datetime

def get_os_pretty_name():
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    except Exception:
        pass
    return platform.platform()

def get_listening_sockets():
    sockets = []
    try:
        out = subprocess.check_output(["ss", "-tulnp"], text=True, stderr=subprocess.DEVNULL)
        for line in out.strip().splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 5:
                proto = parts[0]
                local_addr = parts[4]
                proc_info = parts[6] if len(parts) >= 7 else "kernel/unknown"
                if "users:((" in proc_info:
                    proc_name = proc_info.split('"')[1] if '"' in proc_info else proc_info
                else:
                    proc_name = proc_info
                sockets.append(f"{proto.upper()} {local_addr} ({proc_name})")
    except Exception:
        pass
    return sorted(list(set(sockets)))

def get_ufw_rules():
    rules = []
    try:
        out = subprocess.check_output(["ufw", "status", "numbered"], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if line.strip().startswith("["):
                rules.append(line.strip())
    except Exception:
        pass
    return rules

def main():
    if len(sys.argv) < 6:
        print("Usage: python3 nist_reporter.py <raw_csv> <run_id> <start_time> <end_time> <backup_dir>")
        sys.exit(1)

    raw_csv, run_id, start_time, end_time, backup_dir = sys.argv[1:6]
    txt_report = f"nist_audit_report_{run_id}.txt"
    json_report = f"nist_audit_report_{run_id}.json"

    records = []
    family_stats = {}
    initial_pass = 0
    remediated = 0
    failed = 0

    family_names = {
        "IA": "Identification & Authentication",
        "AC": "Access Control",
        "CM": "Configuration Management",
        "SC": "System & Communications Protection",
        "SI": "System & Information Integrity",
        "AU": "Audit & Accountability"
    }

    with open(raw_csv, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            ts, ctrl_id, fam, name, sev, init_state, action, status = line.split("|")
            records.append({
                "timestamp": ts,
                "control_id": ctrl_id,
                "family": fam,
                "control_name": name,
                "severity": sev,
                "initial_state": init_state,
                "remediation_action": action,
                "final_status": status
            })

            if fam not in family_stats:
                family_stats[fam] = {"total": 0, "passed_initial": 0, "remediated": 0, "compliant_final": 0}
            family_stats[fam]["total"] += 1

            if status == "COMPLIANT":
                initial_pass += 1
                family_stats[fam]["passed_initial"] += 1
                family_stats[fam]["compliant_final"] += 1
            elif status == "REMEDIATED":
                remediated += 1
                family_stats[fam]["remediated"] += 1
                family_stats[fam]["compliant_final"] += 1
            else:
                failed += 1

    total_checks = len(records)
    initial_score = round((initial_pass / total_checks) * 100, 1) if total_checks else 0.0
    final_score = round(((initial_pass + remediated) / total_checks) * 100, 1) if total_checks else 0.0

    hostname = socket.gethostname()
    os_name = get_os_pretty_name()
    kernel = platform.release()
    active_sockets = get_listening_sockets()
    ufw_rules = get_ufw_rules()

    lines = []
    sep_heavy = "=" * 114
    sep_light = "-" * 114

    lines.append(sep_heavy)
    lines.append("                   NIST SP 800-53 REV. 5 AUTOMATED SECURITY ASSESSMENT & REMEDIATION REPORT")
    lines.append(sep_heavy)
    lines.append(f"Assessment ID       : NIST-AUDIT-{run_id}")
    lines.append(f"Target Asset        : {hostname} ({os_name} | Kernel {kernel})")
    lines.append(f"Audit Start Time    : {start_time}")
    lines.append(f"Audit End Time      : {end_time}")
    lines.append(f"Rollback Backup Dir : {backup_dir}")
    lines.append(f"Baseline Standard   : NIST SP 800-53 Rev. 5 / CIS Linux Level 1 Benchmark")
    lines.append(sep_light)
    lines.append("1. EXECUTIVE COMPLIANCE SUMMARY")
    lines.append(sep_light)
    lines.append(f"Total Controls Assessed : {total_checks}")
    lines.append(f"Initial Baseline Score  : {initial_score}% ({initial_pass}/{total_checks} Compliant prior to remediation)")
    lines.append(f"Automated Remediations  : {remediated} Weaknesses Fixed Automatically")
    lines.append(f"Unresolved Findings     : {failed}")
    lines.append(f"Final Compliance Score  : {final_score}% ({initial_pass + remediated}/{total_checks} Controls Compliant)")
    lines.append("")
    lines.append("2. CONTROL FAMILY BREAKDOWN")
    lines.append(sep_light)
    lines.append(f"{'FAMILY ID':<10} | {'NIST CONTROL FAMILY NAME':<38} | {'TOTAL':<7} | {'INITIAL PASS':<14} | {'REMEDIATED':<12} | {'FINAL POSTURE':<13}")
    lines.append(sep_light)
    for fam, st in family_stats.items():
        fname = family_names.get(fam, "Other Security Controls")
        pct = round((st["compliant_final"] / st["total"]) * 100)
        lines.append(f"{fam:<10} | {fname:<38} | {st['total']:<7} | {st['passed_initial']:<14} | {st['remediated']:<12} | {pct}% COMPLIANT")

    lines.append("")
    lines.append("3. TIMESTAMPED CONTROL ASSESSMENT & REMEDIATION LOG")
    lines.append(sep_light)
    header = f"{'TIMESTAMP':<19} | {'NIST ID':<10} | {'SEV':<4} | {'SECURITY CONTROL':<25} | {'INITIAL STATE':<16} | {'REMEDIATION ACTION':<22} | {'STATUS':<10}"
    lines.append(header)
    lines.append(sep_light)

    for r in records:
        lines.append(
            f"{r['timestamp']:<19} | "
            f"{r['control_id']:<10} | "
            f"{r['severity']:<4} | "
            f"{r['control_name'][:25]:<25} | "
            f"{r['initial_state'][:16]:<16} | "
            f"{r['remediation_action'][:22]:<22} | "
            f"{r['final_status']:<10}"
        )

    lines.append(sep_light)
    lines.append("4. ACTIVE FIREWALL POLICY (UFW BOUNDARY PROTECTION - SC-7)")
    lines.append(sep_light)
    if ufw_rules:
        for rule in ufw_rules:
            lines.append(f"  {rule}")
    else:
        lines.append("  No active UFW rules detected.")

    lines.append("")
    lines.append("5. LIVE NETWORK SOCKET & DAEMON INVENTORY (SI-4)")
    lines.append(sep_light)
    if active_sockets:
        for s in active_sockets:
            lines.append(f"  Listening -> {s}")
    else:
        lines.append("  No external listening sockets detected.")
    lines.append(sep_heavy)

    report_content = "\n".join(lines)
    print("\n" + report_content)

    with open(txt_report, "w") as f:
        f.write(report_content + "\n")

    json_payload = {
        "assessment_id": f"NIST-AUDIT-{run_id}",
        "framework": "NIST SP 800-53 Rev. 5",
        "host": {
            "hostname": hostname,
            "os": os_name,
            "kernel": kernel
        },
        "timestamps": {
            "start": start_time,
            "end": end_time,
            "generated_at_iso": datetime.now().isoformat()
        },
        "metrics": {
            "total_controls": total_checks,
            "initial_compliant": initial_pass,
            "remediated_count": remediated,
            "failed_count": failed,
            "initial_compliance_pct": initial_score,
            "final_compliance_pct": final_score
        },
        "controls": records,
        "ufw_rules": ufw_rules,
        "listening_sockets": active_sockets
    }

    with open(json_report, "w") as f:
        json.dump(json_payload, f, indent=2)

    print(f"\n[+] Formal NIST Text Report saved to : {txt_report}")
    print(f"[+] Machine-Readable JSON saved to   : {json_report}")

if __name__ == "__main__":
    main()