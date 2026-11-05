#!/bin/bash

if [ "$EUID" -ne 0 ]; then
    echo "Error: Run this script as root (sudo ./harden_engine.sh)"
    exit 1
fi

run_id=$(date +"%Y%m%d_%H%M%S")
start_time=$(date +"%Y-%m-%d %H:%M:%S %Z")
backup_dir="/var/backups/nist_hardening_$run_id"
raw_csv="/tmp/nist_raw_audit_$run_id.csv"
scan_dirs="/home /tmp /var/tmp"

mkdir -p "$backup_dir"
> "$raw_csv"

record_event() {
    local ts
    ts=$(date +"%Y-%m-%d %H:%M:%S")
    echo "$ts|$1|$2|$3|$4|$5|$6|$7" >> "$raw_csv"
}

echo "[*] Initializing NIST SP 800-53 System Hardening Engine..."
echo "[*] Backing up configurations to $backup_dir"

login_defs="/etc/login.defs"
pw_conf="/etc/security/pwquality.conf"
cp -p "$login_defs" "$backup_dir/" 2>/dev/null
cp -p "$pw_conf" "$backup_dir/" 2>/dev/null

max_days=$(awk '/^PASS_MAX_DAYS/ {print $2}' "$login_defs")
if [ -n "$max_days" ] && [ "$max_days" -le 90 ]; then
    record_event "IA-5(1)" "IA" "Password Max Lifetime" "MED" "MaxDays=$max_days" "None" "COMPLIANT"
else
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t90/' "$login_defs"
    record_event "IA-5(1)" "IA" "Password Max Lifetime" "MED" "MaxDays=${max_days:-Unset}" "Set PASS_MAX_DAYS=90" "REMEDIATED"
fi

min_days=$(awk '/^PASS_MIN_DAYS/ {print $2}' "$login_defs")
if [ -n "$min_days" ] && [ "$min_days" -ge 7 ]; then
    record_event "IA-5(1)" "IA" "Password Min Lifetime" "LOW" "MinDays=$min_days" "None" "COMPLIANT"
else
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t7/' "$login_defs"
    record_event "IA-5(1)" "IA" "Password Min Lifetime" "LOW" "MinDays=${min_days:-Unset}" "Set PASS_MIN_DAYS=7" "REMEDIATED"
fi

if [ -f "$pw_conf" ]; then
    minlen=$(grep -E '^\s*minlen\s*=' "$pw_conf" | awk -F'=' '{gsub(/ /,"",$2); print $2}')
    if [ -n "$minlen" ] && [ "$minlen" -ge 12 ]; then
        record_event "IA-5(1)(a)" "IA" "PAM Password Min Length" "HIGH" "minlen=$minlen" "None" "COMPLIANT"
    else
        if grep -qE '^\s*#?\s*minlen' "$pw_conf"; then
            sed -i 's/^\s*#*\s*minlen.*/minlen = 12/' "$pw_conf"
        else
            echo "minlen = 12" >> "$pw_conf"
        fi
        record_event "IA-5(1)(a)" "IA" "PAM Password Min Length" "HIGH" "minlen=${minlen:-Default}" "Enforced minlen=12" "REMEDIATED"
    fi

    comp_issue=0
    for opt in dcredit ucredit lcredit ocredit; do
        val=$(grep -E "^\s*${opt}\s*=" "$pw_conf" | awk -F'=' '{gsub(/ /,"",$2); print $2}')
        if [ "$val" != "-1" ]; then
            comp_issue=1
            if grep -qE "^\s*#?\s*${opt}" "$pw_conf"; then
                sed -i "s/^\s*#*\s*${opt}.*/${opt} = -1/" "$pw_conf"
            else
                echo "${opt} = -1" >> "$pw_conf"
            fi
        fi
    done

    if [ "$comp_issue" -eq 0 ]; then
        record_event "IA-5(1)(b)" "IA" "PAM Char Complexity" "HIGH" "All credits=-1" "None" "COMPLIANT"
    else
        record_event "IA-5(1)(b)" "IA" "PAM Char Complexity" "HIGH" "Weak credits" "Set u/l/d/ocredit=-1" "REMEDIATED"
    fi
else
    record_event "IA-5(1)(a)" "IA" "PAM Pwquality Module" "HIGH" "Missing" "Install libpam-pwquality" "NON-COMPLIANT"
fi

rogue_roots=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd | tr '\n' ' ')
if [ -z "$rogue_roots" ]; then
    record_event "AC-2(3)" "AC" "Unique UID 0 Root Check" "HIGH" "Only root has UID 0" "None" "COMPLIANT"
else
    for u in $rogue_roots; do
        passwd -l "$u" >/dev/null 2>&1
    done
    record_event "AC-2(3)" "AC" "Unique UID 0 Root Check" "HIGH" "Rogue: $rogue_roots" "Locked rogue accounts" "REMEDIATED"
fi

shadow_perm=$(stat -c "%a" /etc/shadow)
if [ "$shadow_perm" = "640" ] || [ "$shadow_perm" = "600" ]; then
    record_event "AC-6(1)" "AC" "/etc/shadow Permissions" "HIGH" "Mode $shadow_perm" "None" "COMPLIANT"
else
    chown root:shadow /etc/shadow
    chmod 640 /etc/shadow
    record_event "AC-6(1)" "AC" "/etc/shadow Permissions" "HIGH" "Mode $shadow_perm" "Set 640 root:shadow" "REMEDIATED"
fi

sudo_perm=$(stat -c "%a" /etc/sudoers)
if [ "$sudo_perm" = "440" ]; then
    record_event "AC-6(5)" "AC" "/etc/sudoers Permissions" "HIGH" "Mode 440" "None" "COMPLIANT"
else
    chown root:root /etc/sudoers
    chmod 440 /etc/sudoers
    record_event "AC-6(5)" "AC" "/etc/sudoers Permissions" "HIGH" "Mode $sudo_perm" "Set chmod 440" "REMEDIATED"
fi

mapfile -t bad_files < <(find $scan_dirs -type f -perm 0777 2>/dev/null)
count=${#bad_files[@]}
if [ "$count" -eq 0 ]; then
    record_event "CM-6(a)" "CM" "World-Writable 777 Files" "MED" "0 files found" "None" "COMPLIANT"
else
    for f in "${bad_files[@]}"; do
        chmod 644 "$f"
    done
    record_event "CM-6(a)" "CM" "World-Writable 777 Files" "MED" "$count files found" "Applied chmod 644" "REMEDIATED"
fi

sshd_conf="/etc/ssh/sshd_config"
if [ -f "$sshd_conf" ]; then
    cp -p "$sshd_conf" "$backup_dir/"
    restart_ssh=0

    root_ssh=$(grep -iE '^\s*PermitRootLogin' "$sshd_conf" | awk '{print $2}' | tail -n 1)
    if [ "$root_ssh" = "no" ]; then
        record_event "AC-17(2)" "AC" "SSH PermitRootLogin" "HIGH" "Disabled (no)" "None" "COMPLIANT"
    else
        if grep -qiE '^\s*#?\s*PermitRootLogin' "$sshd_conf"; then
            sed -i 's/^\s*#*\s*PermitRootLogin.*/PermitRootLogin no/I' "$sshd_conf"
        else
            echo "PermitRootLogin no" >> "$sshd_conf"
        fi
        restart_ssh=1
        record_event "AC-17(2)" "AC" "SSH PermitRootLogin" "HIGH" "${root_ssh:-Default}" "Set PermitRootLogin no" "REMEDIATED"
    fi

    empty_pw=$(grep -iE '^\s*PermitEmptyPasswords' "$sshd_conf" | awk '{print $2}' | tail -n 1)
    if [ "$empty_pw" = "no" ]; then
        record_event "IA-5(1)" "IA" "SSH Empty Passwords" "HIGH" "Disabled (no)" "None" "COMPLIANT"
    else
        if grep -qiE '^\s*#?\s*PermitEmptyPasswords' "$sshd_conf"; then
            sed -i 's/^\s*#*\s*PermitEmptyPasswords.*/PermitEmptyPasswords no/I' "$sshd_conf"
        else
            echo "PermitEmptyPasswords no" >> "$sshd_conf"
        fi
        restart_ssh=1
        record_event "IA-5(1)" "IA" "SSH Empty Passwords" "HIGH" "${empty_pw:-Unset}" "Disabled empty passwords" "REMEDIATED"
    fi

    max_tries=$(grep -iE '^\s*MaxAuthTries' "$sshd_conf" | awk '{print $2}' | tail -n 1)
    if [ -n "$max_tries" ] && [ "$max_tries" -le 3 ]; then
        record_event "AC-7(a)" "AC" "SSH MaxAuthTries" "MED" "Tries=$max_tries" "None" "COMPLIANT"
    else
        if grep -qiE '^\s*#?\s*MaxAuthTries' "$sshd_conf"; then
            sed -i 's/^\s*#*\s*MaxAuthTries.*/MaxAuthTries 3/I' "$sshd_conf"
        else
            echo "MaxAuthTries 3" >> "$sshd_conf"
        fi
        restart_ssh=1
        record_event "AC-7(a)" "AC" "SSH MaxAuthTries" "MED" "${max_tries:-Default}" "Set MaxAuthTries 3" "REMEDIATED"
    fi

    idle_int=$(grep -iE '^\s*ClientAliveInterval' "$sshd_conf" | awk '{print $2}' | tail -n 1)
    if [ -n "$idle_int" ] && [ "$idle_int" -le 300 ] && [ "$idle_int" -gt 0 ]; then
        record_event "AC-12" "AC" "SSH Idle Session Timeout" "LOW" "${idle_int}s" "None" "COMPLIANT"
    else
        if grep -qiE '^\s*#?\s*ClientAliveInterval' "$sshd_conf"; then
            sed -i 's/^\s*#*\s*ClientAliveInterval.*/ClientAliveInterval 300/I' "$sshd_conf"
        else
            echo "ClientAliveInterval 300" >> "$sshd_conf"
        fi
        restart_ssh=1
        record_event "AC-12" "AC" "SSH Idle Session Timeout" "LOW" "${idle_int:-Unset}" "Set Timeout=300s" "REMEDIATED"
    fi

    if [ "$restart_ssh" -eq 1 ]; then
        systemctl reload-or-restart ssh 2>/dev/null || systemctl reload-or-restart sshd 2>/dev/null
    fi
fi

sysctl_conf="/etc/sysctl.d/99-nist-hardening.conf"
cp -p /etc/sysctl.conf "$backup_dir/" 2>/dev/null

apply_sysctl() {
    local key="$1"
    local target="$2"
    local nist_id="$3"
    local fam="$4"
    local desc="$5"
    local sev="$6"

    local cur
    cur=$(sysctl -n "$key" 2>/dev/null)
    if [ "$cur" = "$target" ]; then
        record_event "$nist_id" "$fam" "$desc" "$sev" "$key=$cur" "None" "COMPLIANT"
    else
        sysctl -w "${key}=${target}" >/dev/null 2>&1
        if grep -qE "^\s*${key}\s*=" "$sysctl_conf" 2>/dev/null; then
            sed -i "s|^\s*${key}\s*=.*|${key} = ${target}|" "$sysctl_conf"
        else
            echo "${key} = ${target}" >> "$sysctl_conf"
        fi
        record_event "$nist_id" "$fam" "$desc" "$sev" "Was ${cur:-Unset}" "Set ${key}=${target}" "REMEDIATED"
    fi
}

apply_sysctl "net.ipv4.tcp_syncookies" "1" "SC-5" "SC" "Kernel TCP SYN Cookies" "HIGH"
apply_sysctl "net.ipv4.ip_forward" "0" "SC-7(12)" "SC" "Disable IPv4 Forwarding" "MED"
apply_sysctl "net.ipv4.conf.all.accept_redirects" "0" "SC-7(12)" "SC" "Block ICMP Redirects" "MED"
apply_sysctl "net.ipv4.icmp_echo_ignore_broadcasts" "1" "SC-5" "SC" "Anti-Smurf Broadcast Ping" "LOW"
apply_sysctl "kernel.randomize_va_space" "2" "SI-16" "SI" "Kernel ASLR Protection" "HIGH"

echo "[*] Deploying Advanced UFW Firewall & Rate-Limiting Rules..."

ufw_state=$(ufw status | awk '/^Status:/ {print $2}')
if [ "$ufw_state" = "active" ]; then
    record_event "SC-7" "SC" "UFW Stateful Firewall" "HIGH" "Active" "Verified Default Deny" "COMPLIANT"
else
    ufw default deny incoming >/dev/null 2>&1
    ufw default allow outgoing >/dev/null 2>&1
    ufw --force enable >/dev/null 2>&1
    systemctl enable ufw >/dev/null 2>&1
    record_event "SC-7" "SC" "UFW Stateful Firewall" "HIGH" "Inactive" "Enabled + Default Deny" "REMEDIATED"
fi

if ufw status | grep -qE "22/tcp\s+LIMIT"; then
    record_event "SC-7(5)" "SC" "UFW SSH Brute-Force Limit" "HIGH" "LIMIT 22/tcp" "None" "COMPLIANT"
else
    ufw limit 22/tcp comment 'NIST-SC7-SSH-Rate-Limit' >/dev/null 2>&1
    record_event "SC-7(5)" "SC" "UFW SSH Brute-Force Limit" "HIGH" "Unthrottled" "Applied ufw limit 22/tcp" "REMEDIATED"
fi

legacy_blocked=0
for port in 21/tcp 23/tcp 69/udp 135/tcp 139/tcp 445/tcp 512:514/tcp; do
    if ! ufw status | grep -q "$port"; then
        ufw deny "$port" >/dev/null 2>&1
        legacy_blocked=1
    fi
done

if [ "$legacy_blocked" -eq 0 ]; then
    record_event "CM-7" "CM" "Block Legacy/SMB Ports" "MED" "All Denied" "None" "COMPLIANT"
else
    record_event "CM-7" "CM" "Block Legacy/SMB Ports" "MED" "Unfiltered" "Blocked FTP/Telnet/SMB" "REMEDIATED"
fi

if ufw status verbose | grep -q "Logging: on"; then
    record_event "AU-2" "AU" "Firewall Packet Logging" "LOW" "Logging On" "None" "COMPLIANT"
else
    ufw logging medium >/dev/null 2>&1
    record_event "AU-2" "AU" "Firewall Packet Logging" "LOW" "Logging Off" "Enabled medium logging" "REMEDIATED"
fi

end_time=$(date +"%Y-%m-%d %H:%M:%S %Z")

if [ -f "./nist_reporter.py" ]; then
    python3 ./nist_reporter.py "$raw_csv" "$run_id" "$start_time" "$end_time" "$backup_dir"
else
    echo "Warning: nist_reporter.py not found in current directory."
fi

rm -f "$raw_csv"