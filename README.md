# Linux Endpoint Security: Defense-in-Depth Implementation

**A comprehensive security project demonstrating detection, prevention and response capabilities on Ubuntu Server through progressive hardening, custom IDS rules, and automated threat response.**

---
## 📋 Table of Contents

- [Project Overview](#project-overview)
- [Skills Demonstrated](#skills-demonstrated)
- [Phase 1: Initial Access and Baseline Configuration](#phase-1-initial-access-and-baseline-configuration)
- [Phase 2: Intrusion Detection System (Snort)](#phase-2-intrusion-detection-system-snort)
- [Phase 3: Core Security Hardening](#phase-3-core-security-hardening)
- [Phase 4: Automated Intrusion Prevention with Fail2Ban](#phase-4-automated-intrusion-prevention-with-fail2ban)
- [Project Conclusion](#project-conclusion)

---
## Project Overview

This project demonstrates building enterprise-grade endpoint security on Ubuntu Server using open-source tools. Starting from a minimal installation with default configurations, I progressively implemented multiple security layers following defense-in-depth principles.

**What This Project Covers:**

**Phase 1 - Baseline & Initial Access:**
- Documented initial security posture (services, network exposure, SSH configuration)
- Established secure remote access with basic firewall rules
- Created security baseline for measuring improvements

**Phase 2 - Network Intrusion Detection:**
- Deployed Snort IDS with custom detection rules
- Tuned thresholds to balance sensitivity and false positives
- Validated detection against real attack patterns (nmap scans, SSH brute force, ICMP floods, UDP scans)

**Phase 3 - System Hardening:**
- SSH hardening (key-only auth, non-standard port, session timeouts, user restrictions)
- Firewall configuration (default-deny policy, rate limiting, protocol blocking, logging)
- Password policy enforcement (14-character minimum, complexity requirements)
- File integrity monitoring (auditd for critical system files)
- Rootkit detection (rkhunter for system binary verification)
- Automated security patching (unattended-upgrades verification)

**Phase 4 - Automated Intrusion Prevention:**
- Fail2Ban integration with UFW firewall
- Automated IP blocking based on authentication failure patterns
- Real-time attack simulation demonstrating <5 second response time
- Complete detection-to-response pipeline (Snort alerts → Fail2Ban blocks)

**Goal** To build a defense-in-depth system where multiple security controls work together, so even if one layer fails, another would catch the threat.

### Skills I Demonstrated

**Linux System Administration:**
- Service management and minimization
- File permissions and ownership
- Network configuration
- Package management
- Log analysis and correlation

**Security Implementation:**
- Intrusion detection system configuration
- Intrusion prevention automation
- Firewall management (UFW)
- SSH hardening
- Access control and authentication
- File integrity monitoring
- Security auditing

**Security Operations:**
- Baseline documentation
- Rule creation and tuning
- Attack simulation and validation
- Incident detection and response
- Log correlation across multiple systems

---

## Phase 1: Initial Access and Baseline Configuration

## 1.1 Lab Environment

I used VirtualBox to create two VMs on the same NAT network, this setup mimics a realistic scenario where an attacker had gained access to the same network as the target server.

**Ubuntu Server 24.04 LTS** - Target system
- IP: 10.0.2.8
- Minimal installation (fewer services = smaller attack surface)

**Kali Linux 2024** - For security testing  
- IP: 10.0.2.15

**Network diagram:**
```
┌─────────────────────────────────────────────┐
│         VirtualBox NAT Network              │
│              (10.0.2.0/24)                  │
│                                             │
│  ┌─────────────────┐   ┌─────────────────┐│
│  │   Kali Linux    │   │  Ubuntu Server  ││
│  │   (Attacker)    │──▶│ (Target/Defend) ││
│  │   10.0.2.15     │   │   10.0.2.8      ││
│  │                 │   │                 ││
│  │  Tools:         │   │  Security:      ││
│  │  • nmap         │   │  • Snort IDS    ││
│  │  • ping flood   │   │  • Fail2Ban IPS ││
│  │  • SSH brute    │   │  • UFW Firewall ││
│  └─────────────────┘   └─────────────────┘│
└─────────────────────────────────────────────┘
```

I used NAT Network** because it places both VMs on the same subnet (10.0.2.0/24), allowing them to communicate freely with each other. Both VMs can also reach the internet through the NAT gateway. This setup mimics a real internal network scenario where an attacker is already inside and can reach the target system directly, which is the threat model I'm defending against.

**Production difference:** In a real enterprise environment, I'd have proper network segmentation with VLANs, DMZs, and multiple firewall layers. This lab simulates a flat internal network where both systems can communicate directly.

### 1.2 Ubuntu Server Initial Login

After installing Ubuntu Server 24.04 LTS (minimized), I logged in directly through the VirtualBox console to begin the security configuration process.

**Checking network configuration:**
```bash
# Verify IP address
ip addr show

# Output:
# enp0s3: inet 10.0.2.8/24
```

The Ubuntu Server received IP address **10.0.2.8** from the VirtualBox NAT network DHCP server.

**Checking SSH Status**

Before establishing remote access, I verified that SSH was installed and running on the Ubuntu server.

*SSH service status:*
```bash
sudo systemctl status sshd
```
*Key observations:*
-  SSH service is **active (running)**
-  SSH is **enabled** (starts automatically on boot)
-  Listening on **port 22** (default)
-  istening on all interfaces (0.0.0.0 and ::)

This confirms SSH is ready for remote connections.

**Checking UFW Firewall Status**

Next, I checked the firewall status to understand the baseline security posture.

*UFW status:*
```bash
sudo ufw status verbose
```

UFW firewall was **inactive** by default on Ubuntu Server minimized installation. This means:
- All incoming connections are allowed
- No firewall protection
- SSH is exposed without filtering
- Logging is set to low

This is a security risk that needs to be addressed.

**Enabling UFW and Allowing SSH**

Before enabling the firewall, I needed to allow SSH connections so that I can be able to remotely access the server from the Kali vm.

*Allowing SSH through firewall:*
```bash
# Allow SSH from anywhere (initial setup)
sudo ufw allow in 22/tcp 

# Enable UFW
sudo ufw enable
```
**Verifying UFW status after enabling:**
```bash
sudo ufw status numbered
```
**Security posture after enabling UFW:**
-  Firewall is now **active**
-  SSH access is **allowed** (port 22)
-  All other incoming connections are **denied** (default policy)
-  Firewall starts automatically on boot

---

### 1.3 Initial Setup and Baseline

With SSH enabled and the firewall configured, I tested remote access from the Kali VM.

**From Kali Linux terminal:**
```bash
# Test SSH connection to Ubuntu Server
ssh ubuntu@10.0.2.8
```
**SSH connection was successful!** and I could now manage the Ubuntu server remotely from Kali Linux.

Before making any security changes, I documented the system's initial state. I can't measure changes or improvement if I don't know where I started. This also demonstrates a methodical approach which is required in a production environment. 

**Checking running services and network exposure:**
```bash
sudo systemctl list-units --type=service --state=running | tee pre_hardening.txt
sudo ss -tuln | tee pre_network.txt
```
![Initial OS Configuration](screenshots/phase1/os0.png)

**Result:**
- *14 loaded units*
- *Port 22 (TCP):* SSH listening on all interfaces (0.0.0.0 and ::)
- *Port 53 (TCP/UDP):* systemd-resolved on localhost only (127.0.0.53)
- *Port 68 (UDP):* DHCP client (getting IP from VirtualBox)

The service count was low (14) because I chose the minimized installation during setup, fewer services means a smaller attack surface to defend. Only SSH was exposed to the network and it was listening on port 22 across all network interfaces (0.0.0.0 and ::), which meant any system on the network could attempt to connect. 

**Checking SSH configuration**
I checked the initial sshd configuration, 
```bash
sudo grep "^Port\|^PermitRootLogin\|^PasswordAuthentication\|^MaxAuthTries\|ClientAliveInterval\|ClientAliveCountMax" /etc/ssh/sshd_config
```
![SSH Initial Status](screenshots/phase1/os1.png)

**Current configuration:**
- **Port 22** - Standard SSH port, heavily scanned by automated tools. Attackers don't need to guess or probe; they know SSH will be here.
- **PermitRootLogin prohibit-password** - Root login is allowed via SSH key authentication not password authentication. However, allowing root access at all means that any  compromise of the root account gives complete system control. Best practice is to disable direct root login entirely and use privilege escalation for administrative tasks.
- **PasswordAuthentication yes** - Password-based authentication is enabled. This is a brute force vector, attackers can attempt username/password combinations against user accounts. Even with rate limiting, weak passwords or common credential patterns can be exploited.
- **MaxAuthTries 6** - The SSH daemon allows 6 failed authentication attempts before closing the connection. This is generous. An attacker gets 6 chances to guess credentials for each connection, they can try multiple passwords per connection. Reducing this to 2-3 attempts makes brute forcing significantly harder.
- **ClientAliveInterval 0** - No keep-alive mechanism for idle sessions. Sessions stay open indefinitely unless the user manually disconnects or the connection drops. An attacker who gains a shell has unlimited time to work without worry of session timeout.
- **ClientAliveCountMax 3** - After sending keep-alive probes, the connection closes after 3 unanswered probes. However, with ClientAliveInterval set to 0, these probes are never sent.

Each of these settings makes SSH more vulnerable to attack, particularly against brute force and session hijacking.

**SSH File Backup and Sensitive files permissions**

I created a back up file before configuration changes in order to have something to fall back on if it fails. I also checked for file permissions of sensitive files

```bash
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
sudo ls -l /etc/passwd /etc/shadow /etc/ssh/sshd_config 
```
![Backup and file Config](screenshots/phase1/os2.png)

- **/etc/passwd (644)** - Readable by all users, but this is correct. It contains user metadata (usernames, UIDs, home directories), not passwords.
- **/etc/shadow (640)** - Readable and writable by root, readable by the shadow group with no access for others. This is correct, it contains password hashes. The shadow group allows certain system utilities to read password information without requiring full root privileges, following the principle of least privilege.
- **/etc/ssh/sshd_config (644)** - Readable by all users, writable by root only. While this doesn't pose a major security risk since sshd_config doesn't contain secrets, best practice would be to restrict this to **600** (readable and writable by root only) to follow the principle of least privilege and prevent information disclosure about SSH configuration.


The system was functional but not hardened. 

---

## Phase 2: Intrusion Detection System (Snort)

**Why Start with Detection?**

I implemented detection before prevention because I need visibility before I can respond. Detection gives insight on the full attack pattern or context. Snort runs as a network-based IDS (Intrusion Detection System), it watches traffic at the packet level and generates alerts based on rule patterns without blocking anything. With Snort running first, I could Tune thresholds based on real traffic and Validate that prevention systems were responding to actual threats.

### 2.1 Installing and Configuring Snort
```bash
sudo apt update
sudo apt install snort -y
```
During installation, I set the Interface which Snort should listen on as enp0s3 which is my network interface. 

**Configuring and Verifying HOME_NET IP**

```bash
sudo nano /etc/snort/snort_config
sudo grep "ipvar HOME_NET" /etc/snort/snort.conf
# Output: ipvar HOME_NET 10.0.2.0/24 ✓
```

HOME_NET defines my protected network. Snort uses this to understand traffic directionality; rules can specify traffic coming *into* HOME_NET versus going *out of* it. Getting this right is critical for rules to work properly.

```bash
# Test configuration for syntax errors
sudo snort -T -c /etc/snort/snort.conf
```
The validation test loads all rules, initializes preprocessors, and checks for configuration errors before actually running Snort.

### 2.2 Creating Custom Detection Rules

Rather than relying solely on built-in rules, I created custom rules to demonstrate understanding of IDS logic and rule tuning. I focused on four common attack patterns.
```bash
sudo nano /etc/snort/rules/local.rules
```

**My four custom rules:** (full rule file: [local.rules](config/local.rules)):
```bash
# Rule 1: TCP SYN Scan Detection (nmap and port scanners)
alert tcp any any -> $HOME_NET any (msg:"Possible NMAP scan detected"; flags:S; threshold: type threshold, track by_src, count 10, seconds 5; sid:1000001; rev:1;)

# Rule 2: ICMP Flood Detection (ping floods)
alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Flood Detected"; itype:8; threshold: type threshold, track by_src, count 50, seconds 5; sid:1000002; rev:1;)

# Rule 3: SSH Brute Force Detection
alert tcp any any -> $HOME_NET 22 (msg:"Possible SSH Brute Force Attempt"; flags:S; threshold: type threshold, track by_src, count 5, seconds 60; sid:1000003; rev:1;)

# Rule 4: UDP Port Scan Detection
alert udp any any -> $HOME_NET any (msg:"Possible UDP Port Scan Detected"; threshold: type threshold, track by_src, count 10, seconds 5; sid:1000004; rev:1;)
```

**Understanding Rule Syntax**
```bash
alert tcp any any -> $HOME_NET any (msg:"Possible NMAP scan detected"; flags:S; threshold: type threshold, track by_src, count 10, seconds 5; sid:1000001; rev:1;)
```

**Rule components:**

- **`alert`** - Action (generate an alert; don't silently log)
- **`tcp`** - Protocol to monitor
- **`any any`** - From any source IP and source port
- **`-> $HOME_NET any`** - Directed toward my network, any destination port
- **`msg:"..."`** - Human-readable alert description
- **`flags:S`** - Match only TCP packets with the SYN flag set (used to initiate connections; port scanners send SYN to many ports rapidly)
- **`threshold: type threshold, track by_src, count 10, seconds 5`** - Alert only when a single source sends 10+ matching packets in 5 seconds
- **`sid:1000001`** - Signature ID (unique identifier; custom rules use IDs above 1000000)
- **`rev:1`** - Revision number (version 1 of this rule)


**Why the threshold is critical:**

Without the threshold, this rule would trigger on every single TCP SYN packet including normal web browsing (browsers open 6-8 simultaneous connections), SSH sessions, database connections, etc. The would lead to false positives.


### 2.3 Testing Detection

To validate all the rules actually work against real attacks, I started Snort and let it log to `/var/log/snort/alert`:
```bash
sudo snort -c /etc/snort/snort.conf -i enp0s3
```
From Kali, I launched attacks to test each rule:

![Snort Alert Trigger](screenshots/phase2/snort_alert_trigger.png)

**Test 1: TCP Port Scan**
```bash
nmap -sS 10.0.2.8
```

**Analyzing results:**

**Note on command methodology:** During analysis, I used echo statements and separated commands for clear documentation purpose; showing each verification step explicitly. 

**Rule Tunning** I tested three threshold variations for the nmap port scanning to demonstrate the tradeoff between sensitivity and false positives:

**Baseline(Rule 1000001):**
```bash
count 10, seconds 5
```
![Nmap Baseline Alert](screenshots/phase2/nmap_baseline_alert.png)

**Sensitive variant(Rule 1000005):**
```bash
count 5, seconds 10
```
![Nmap Sensitive Alert](screenshots/phase2/nmap_sensitive_alert.png)

**Conservative variant (Rule 1000006):**
```bash
count 20, seconds 5
```
![Nmap Conservative Alert](screenshots/phase2/nmap_conservative_alert.png)

**Testing with nmap -sS (TCP SYN scan):**

| Rule Version | Alerts Generated |
|--------------|-----------------|
| Baseline | 200 alerts |
| Sensitive | 400 alerts |
| Conservative | 100 alerts |

I chose the baseline threshold because it provided clear detection (200 alerts) without excessive noise. The sensitive version generated too many alerts for the same scan, while the conservative version was too lenient.

**Production approach:** In a production environment, I would test each rule variation against multiple scan types: slow scans (nmap -T2), standard scans (nmap -sS), and aggressive scans (nmap -T4)—to understand how threshold sensitivity affects detection of different attack speeds. This would require weeks of testing with actual network traffic to find the optimal balance between catching real attacks and avoiding false positives and would continuously adjust as traffic patterns change.

**You can't properly tune IDS rules without understanding your environment's normal behavior.**


**Test 2: UDP Port Scan (Rule 1000004)**
```bash
nmap -sU --top-ports 100 10.0.2.8
```

I used `--top-ports 100` to speed it up (only scan 100 most common UDP ports instead of all 65535).

![Snort UDP Alert](screenshots/phase2/snort_udp_alert.png)

**Results:** 208 detections. The UDP rule successfully caught the scanning pattern.


**Test 3: SSH Brute Force (Rule 1000003)**

**SSH Rule Validation: Manual SSH Testing**

Before finalizing the SSH rule threshold, I tested it with manual connection attempts with deliberate wrong passwords:

![Snort Manual SSH Trigger](screenshots/phase2/snort_manual_ssh_trigger.png)

I entered the wrong password multiple times manually. Snort filtered 2 connection attempts but did not generate an alert:

![Snort Manual SSH Alert](screenshots/phase2/snort_manual_ssh_alert.png)

The manual attempts were slower than the threshold of 5 attempts in 60 seconds. This is the correct behavior; a user typing wrong passwords by mistake shouldn't trigger a brute force alert. The rule is finely tuned to catch automated attack tools that target the SSH port rapidly, not legitimate users making occasional mistakes.

**This validated that the SSH rule threshold was appropriate.**

I then simulated rapid connection attempts to mimick automated bruteforce attempt that can exceed the threshold.

```bash
for i in {1..6}; do ssh -o ConnectTimeout=2 user@10.0.2.8 2>/dev/null & done
```
**Checking results:**

![Snort Automated SSH Alert](screenshots/phase2/snort_automated_ssh_alert.png)

1 SSH brute force attempt was detected (sid:1000003). The SSH rule triggered when rapid connection attempts to port 22 exceeded the threshold of 5 attempts in 60 seconds.

The rule caught the rapid connection pattern.  This demonstrates the rule is properly tuned; it catches automated attack tools but doesn't trigger on legitimate user mistakes which is slower.


**Test 4: ICMP Flood (Rule 1000002)**
```bash
sudo ping -f 10.0.2.8
```
I used the `-f` flag to "flood"; send pings as fast as possible with no delay. 

**Checking results:**
```bash
sudo grep "\[1:1000002:" /var/log/snort/alert | wc -l
```

![Snort ICMP Alert](screenshots/phase2/snort_icmp_alert.png)

Snort detected 99 ICMP flood attempts. Custom rule (sid:1000002) successfully identified ping flood when threshold of 30 ICMP Echo Requests in 5 seconds was exceeded. Normal pings (1 per second) do not trigger this rule.

**What This Demonstrates**

- **Rule effectiveness:** All four rules detected their target attack patterns with appropriate thresholds.

- **Threshold tuning trade-offs:** The nmap tests showed how threshold choices affect detection volume. Baseline provided good coverage without excessive alerts.

- **SSH rule precision:** The rule correctly distinguished between user mistakes (manual attempts didn't trigger) and automated attack tools (rapid connections did trigger).

- **Network-level detection:** Snort identified all attack patterns at the packet level without needing to see application data.

### 2.4 Key Takeaways

This phase demonstrated the core IDS principles: defining detection patterns, tuning thresholds to reduce false positives and validating rules against real attack traffic. All four custom rules successfully detected their target patterns.

**In production,** I'd test these rule variations against different attack speeds and real traffic patterns over weeks before finalizing thresholds. Also, an IDS would have thousands of rules from threat intelligence feeds, centralized logging to a SIEM and 24/7 monitoring but the fundamental principles: pattern matching, threshold tuning, alert validation is the same.

---

## Phase 3: Core Security Hardening

With detection in place, I could now harden the system knowing I'd see any attacks that occurred during or after the hardening process.

### 3.1 SSH Hardening

SSH was the primary attack surface; the only service exposed to the network. Hardening SSH would have the biggest security impact. I had earlier backed up the config file as shown in phase1.

**Always backing up before modifying critical configs is a security standard to ensure that I could easily revert if I broke something.**

**Editing configuration:**
```bash
sudo nano /etc/ssh/sshd_config
```
**Changes I made:**

![SSHD Config Hardening](screenshots/phase3/sshd_config_hardening.png)

```bash
# Change from default port (security through obscurity + practicality)
Port 2222

# Disable direct root login
PermitRootLogin no

# Limit authentication attempts
MaxAuthTries 3

# Disable password authentication (force keys only)
PasswordAuthentication no

# Ensure public key authentication is enabled
PubkeyAuthentication yes

# Session timeout settings
ClientAliveInterval 300
ClientAliveCountMax 3

# Restrict to specific users
AllowUsers ubuntu
```

**Why each change matters:**

- **Port 2222 (vs default 22):**
Port 22 is the first thing automated bots attack, using non-standard port eliminates ~99% of automated bot attacks. However, skilled attackers can still find it with nmap. This is "security through obscurity" but it's practical obscurity.

- **PermitRootLogin no:**
Direct root login means attacker with root password has full system access immediately. If disabled, even if attacker gets root password, they can't login directly. This ensures users must login as regular user, then use `sudo` to get root privileges which: forces two-factor authentication (user password + sudo password), logs all privilege escalation in sudo log, limits blast radius of compromised credentials.

- **MaxAuthTries 3 (vs 6):**
The initial 6 attempts per connection gives attackers too many guesses, limiting to 3 attempts per connection slows brute force attacks significantly without affecting legitimate users (most people don't mistype their password 3+ times)

- **PasswordAuthentication no:**
Passwords can be guessed/brute forced given enough time and resources, SSH keys use 2048+ bit encryption which is practically impossible to brute force thereby eliminating password-based attacks

- **ClientAliveInterval 300 + ClientAliveCountMax 3:**
Sessions can persist indefinitely, giving attackers unlimited time to work. With these settings, idle sessions timeout after 300 seconds (5 minutes) of inactivity. An attacker with a reverse shell would be disconnected if they go inactive, limiting their window.

- **AllowUsers ubuntu:**
Explicitly whitelisting only the ubuntu user prevents any other accounts from SSH access. Even if an attacker creates a new account on the system, they can't use SSH to access it.

I also verfied that

- **HostbasedAuthentication no and IgnoreRhosts yes:**
These disable older, less secure authentication methods that rely on system trust relationships rather than cryptography.

Host-based authentication allows SSH login based on the client machine's identity (checking `.rhosts` or `/etc/hosts.equiv`), not the user's credentials. This is dangerous because: It trusts the remote machine's hostname/IP instead of verifying user credentials, if an attacker controls the remote machine or spoofs its hostname, they can login as any user.

`.rhosts` files can be modified by users, creating privilege escalation vectors, disabling this forces SSH to rely on cryptographic keys or passwords instead of network-based trust

Disabling both options removes this legacy attack surface entirely.

**Testing SSH after hardening:**
Initially, I tried connecting to the standard port 22, connection failed because SSH was no longer listening on port 22. Then, I tested the new hardened configuration on port 2222:

```bash
ssh -p 2222 ubuntu@10.0.2.8
# Enter passphrase for key '/home/kali/.ssh/id_ed25519':
# Welcome to Ubuntu 24.04.3 LTS
```

![SSHD Config Hardening Test](screenshots/phase3/sshd_config_hardening_test.png)

SSH connection successful on port 2222 using key-based authentication. No password authentication was possible; the system would reject password attempts entirely because `PasswordAuthentication` is disabled.

### 3.2 Password Policy Enforcement

Strong passwords are essential. Although I disabled password authentication for SSH, system users and future administrators need password requirements enforced. This ensures that if an attacker gains local access to the system or targets any future service that uses password authentication, they cannot easily brute force weak passwords. 

**Installing password quality enforcement:**
```bash
sudo apt install libpam-pwquality -y
```

Ubuntu's minimal installation includes basic password checks via PAM (Pluggable Authentication Modules). However, robust password policies require the libpam-pwquality package.

**Configuring password quality settings:**
```bash
sudo nano /etc/security/pwquality.conf
```

![Password Policy Config](screenshots/phase3/password_policy_config.png)

**Why each setting is standard industry practice:**

**minlen = 14:**

Minimum password length of 14 characters. NIST guidelines recommend at least 12 characters for system passwords. 14 provides a safety margin. Each additional character exponentially increases brute force time. A 14-character password with mixed character types has approximately 2^92 possible combinations—billions of years to brute force even with specialized hardware.

**difok = 5:**

At least 5 characters must differ from the previous password. This prevents attackers from exploiting common password patterns. Users often change passwords by appending a number (Password1 → Password2 → Password3). An attacker who compromises a previous password could guess the new one by trying incremental changes. Requiring 5 different characters stops this attack pattern.

**lcredit = -1, ucredit = -1, dcredit = -1, ocredit = -1:**

Each `-1` requires at least 1 character from that category:
- **lcredit = -1:** At least 1 lowercase letter
- **ucredit = -1:** At least 1 uppercase letter  
- **dcredit = -1:** At least 1 digit
- **ocredit = -1:** At least 1 special character

Character diversity prevents dictionary attacks. A password using only lowercase letters can be cracked with a dictionary of ~100,000 common words. Adding uppercase, numbers, and special characters expands the search space exponentially, making dictionary attacks impractical.


**Testing the password policy:**
```bash
sudo adduser testuser
```

![Password Policy Test](screenshots/phase3/password_policy_test.png)

The system rejected a password which didn't meet the policy enforcement which would force the user or admin to create a stronger password. 

### 3.3 Automatic Security Updates

Unpatched systems are vulnerable to known exploits. Automating security updates ensures patches are applied without manual intervention.

**Checking automatic update configuration:**
```bash
sudo cat /etc/apt/apt.conf.d/20auto-upgrades
```

![Patch Management](screenshots/phase3/patch_management.png)

The system is already configured to:
- Update package lists daily (`APT::Periodic::Update-Package-Lists "1"`)
- Download security updates daily (`APT::Periodic::Unattended-Upgrade "1"`)

This means security patches are automatically downloaded and installed without requiring administrator action. This configuration ensures the system is patched within 24 hours.

### 3.3 Rootkit Detection with Rkhunter

Detecting rootkits and malicious system modifications is critical for identifying compromised systems. Rkhunter scans for known rootkits, verifies system binary integrity and checks for suspicious files commonly associated with advanced persistent threats.

```bash
sudo apt install rkhunter -y
sudo rkhunter --check --skip-warnings --report-warnings-only
```

![Rkhunter Scan Summary](screenshots/phase3/rkhunter_scan_summary.png)

Rkhunter performed comprehensive checks:
- **137 system binaries checked** for unauthorized modifications
- **2 hidden files flagged as warnings**:
  - `/etc/.resolv.conf.systemd-resolved.bak`
  - `/etc/.updated`
- **495 known rootkit signatures checked** - 0 rootkits detected

The scan took 7 minutes and 12 seconds, with all results logged to `/var/log/rkhunter.log`.

**Investigating the flagged files:**
```bash
# Check the hidden files that triggered warnings
sudo grep -iE "Hidden file|Warning" /var/log/rkhunter.log
ls -l /etc/.resolv.conf.systemd-resolved.bak
ls -l /etc/.updated
sudo nano /etc/.resolv.conf.systemd-resolved.bak
sudo nano /etc/.updated
```

![Rkhunter False Positive Verify](screenshots/phase3/rkhunter_false_positive_verify.png)

**Analysis:** Both files are legitimate system files:
- `/etc/.resolv.conf.systemd-resolved.bak` - Backup created by systemd-resolved during network configuration
- `/etc/.updated` - Timestamp file created by the package management system

These are benign system files, not security threats. This demonstrates an important security operations principle: **automated security tools require human analysis to distinguish between legitimate system behavior and actual threats**.

**Updating the baseline:**
```bash
sudo rkhunter --propupd  # Update file properties database
```

After establishing the baseline, rkhunter can now detect if critical system binaries (like `/bin/ls`, `/usr/bin/ssh`, `/sbin/init`) are replaced or modified; a common rootkit technique. While rkhunter doesn't provide real-time monitoring, scheduled scans (via cron) enable periodic verification that the system hasn't been compromised at the rootkit level.

**Security value:** Rkhunter focuses specifically on rootkit detection—sophisticated malware that operates at a deep system level and attempts to hide its presence. This complements other security controls by providing visibility into attacks that bypass application layer defenses.

### 3.4 Security Event Logging with auditd

Detecting security incidents requires comprehensive visibility into system activity. The Linux Audit daemon (auditd) provides detailed logging of security-relevant events, including file modifications, system calls and authentication attempts which creates a forensic audit trail for incident investigation.

```bash
sudo apt install auditd -y
```

**Adding custom audit rules for critical system files:**
```bash
sudo auditctl -w /etc/passwd -p wa -k passwd_changes
sudo auditctl -w /etc/shadow -p wa -k shadow_changes
sudo auditctl -w /etc/ssh/sshd_config -p wa -k sshd_config_changes
```

**Verifying active rules:**
```bash
sudo auditctl -l
```
![File Monitoring Config](screenshots/phase3/file_monitoring_config.png)

**Rule configuration:**
- `-w /path/to/file` - Watch this file for events
- `-p wa` - Log **w**rite operations and **a**ttribute changes (permissions, ownership)
- `-k tag_name` - Tag events for easy filtering in log searches

**Why these files matter:**
- **`/etc/passwd`** - User account database; modifications indicate potential account manipulation
- **`/etc/shadow`** - Password hashes; changes could indicate privilege escalation attempts
- **`/etc/ssh/sshd_config`** - SSH configuration; modifications could enable backdoor access

**Security value:** These audit rules create a forensic trail of critical file modifications. If an attacker compromises the system and attempts to create backdoor accounts, modify SSH settings, or escalate privileges, these actions are logged with timestamps, process IDs and user context for incident investigation.

I understand that rules added with `auditctl` are active immediately but not persistent across reboots. For production environments, these rules would be added to `/etc/audit/rules.d/audit.rules` to survive system reboots. 

### 3.5 File Permissions Hardening

Critical system files need restrictive permissions to prevent unauthorized access or modification.

**Hardening SSH config permissions:**
```bash
sudo chmod 600 /etc/ssh/sshd_config
```

![SSHD File Permission Hardening](screenshots/phase3/sshd_file_permission_hardening.png)

Changed from 644 (readable by all) to 600 (root only).

**Why SSH config must be root-only:**

The sshd_config file contains critical security settings that reveal the system's authentication and access controls:
- Non-standard port numbers (2222 instead of 22)
- Which users are allowed to login (AllowUsers ubuntu)
- Authentication methods enabled/disabled
- Timeout settings and connection limits
- Key exchange algorithms and ciphers

If unprivileged users can read this file, they can understand the system's security posture. With 644 permissions (group and other readable), any user on the system could read these configuration details. Restricting to 600 ensures only the root user who manages SSH can access this sensitive configuration information.

### 3.6 Firewall Hardening

![UFW Hardened](screenshots/phase3/ufw_hardened.png)

With SSH moved to port 2222 and other services hardened, I updated firewall rules to implement defense-in-depth security controls.

**I Removed the old SSH rule and added hardened SSH rule with rate limiting :**
```bash
sudo ufw delete allow 22/tcp
sudo ufw limit 2222/tcp comment 'Hardened SSH with rate limiting'
```

The `limit` action automatically rate-limits connections (maximum 6 connections per 30 seconds from a single IP), preventing rapid brute force attempts.

**Defense-in-Depth: Firewall Rate Limiting + SSH Hardening**

The firewall rate limiting complements the SSH configuration hardening from the previous step:

- **Network Layer (Firewall)**: Rate limiting blocks rapid connection attempts, preventing automated brute force tools and resource exhaustion attacks
- **Application Layer (SSH)**: `MaxAuthTries 3` limits authentication attempts per connection, and key-only authentication makes password guessing impossible

This layered approach ensures that even if an attacker bypasses one control, subsequent layers prevent compromise. Rate limiting also generates detectable patterns in logs, which enables intrusion detection systems to identify and respond to attacks.

**Restricting DNS to internal network:**
```bash
sudo ufw allow from 10.0.2.0/24 to any port 53 comment 'DNS - internal only'
```

I restricted DNS to the internal network (10.0.2.0/24) to demonstrate prevention of:
- DNS amplification attacks (system being used as reflector)
- External reconnaissance using DNS queries
- Unauthorized DNS resolution from untrusted networks

**Enabling firewall logging:**
```bash
sudo ufw logging medium
```

Logging was enabled at the **medium** level to demonstrate an optimal balance for security monitoring:

- New connections, packets that don't match existing connections, and rate-limited connection attempts are logged. This logs security relevant events without generating excess log volume from routine established connections but provides visibility into connection attempts, blocked traffic patterns, and potential reconnaissance activities

**Logging level considerations:**
- **Low**: Only logs blocked packets (insufficient for comprehensive monitoring)
- **Medium** (current): Logs new connections and blocked packets (recommended for most environments)
- **High**: Logs all packets including established connections (appropriate for high-security environments with dedicated log management infrastructure but generates significant log volume)
- **Full**: Logs everything with rate limiting disabled (only for debugging, not production)

**Explicit deny rules for legacy protocols:**
```bash
sudo ufw deny 23/tcp comment 'Telnet - insecure'
sudo ufw deny 21/tcp comment 'FTP - insecure'
sudo ufw deny 69/udp comment 'TFTP - insecure'
sudo ufw deny 445/tcp comment 'Block SMB'
sudo ufw deny 139/tcp comment 'Block NetBIOS'
```

**Industry Standard vs. Portfolio Demonstration:**

In production environments, the security industry standard is **implicit deny all, then explicit allow** of required protocols. With UFW's default deny policy, these explicit deny rules are technically redundant; the protocols are already blocked.

However, I've included them in this portfolio project to demonstrate:

1. **Defense-in-Depth**: Explicit denies can provide an additional layer of protection against misconfiguration. If the default policy were ever accidentally changed, these rules would still block insecure protocols.

2. **Policy Documentation**: The explicit rules can serve as inline documentation of protocols that are explicitly prohibited by security policy, making audits and reviews clearer.

**Production Environment Approach:**

In a production environment, I would implement the security industry standard: **implicit deny all with explicit allow** for required services only. This approach:

- **Minimizes attack surface**: Only necessary ports are accessible
- **Reduces rule complexity**: Fewer rules to manage and audit
- **Follows least privilege**: Services must be intentionally permitted rather than explicitly blocked
- **Simplifies maintenance**: Adding new services requires explicit approval, preventing shadow IT

**Alternative approach for enhanced monitoring:**

While the default deny model is the foundation, explicit deny rules for high-risk protocols (FTP, Telnet, SMB) can be added with logging and rate limiting for security monitoring purposes:

- **Threat detection**: Connection attempts to known insecure protocols indicate misconfigured applications, reconnaissance activity or potential lateral movement
- **Incident response**: Logged attempts provide forensic evidence and early warning indicators
- **Compliance requirements**: Many security frameworks require documented blocking and monitoring of prohibited protocols

This will also require **Log flooding protection; Rate-limited logging (e.g., 5 events/minute)** to prevents attackers from using denied connections to exhaust disk space or hide malicious activity in log noise

This hybrid approach of default deny foundation with selective logged denies, balances operational simplicity with comprehensive security monitoring for incident detection and response.

### 3.7 Security Posture: Phase 1 Baseline vs. Phase 3 Hardened

| Component | Phase 1 (Baseline) | Phase 3 (Hardened) | Security Impact |
|-----------|-------------------|-------------------|-----------------|
| SSH Port | 22 (default) | 2222 (non-standard) | Reduces automated bot traffic by ~99% |
| Authentication Method | Password-based | Key-only (PasswordAuthentication no) | Eliminates brute force attack vector |
| Root Login | Permitted | Disabled (PermitRootLogin no) | Requires privilege escalation via sudo |
| User Access Control | All users | Specific user only (AllowUsers ubuntu) | Restricts SSH access to authorized accounts |
| Max Auth Tries | 6 | 3 | Reduces authentication window per connection |
| Session Timeout | No timeout | 15 minutes (ClientAliveInterval 300, CountMax 3) | Terminates abandoned sessions automatically |
| Password Policy | Default | 14-char minimum + complexity | Enforces strong credentials for local accounts |
| Patch Management | Manual | Automated daily (unattended-upgrades) | Security updates deployed within 24 hours |
| File Integrity | None | rkhunter baseline | Detects rootkit infections and system binary tampering |
| Audit Framework | Basic syslog | auditd rules | Comprehensive forensic logging of critical file modifications |
| Firewall Rules | Single allow rule | Rate limiting + protocol blocking + medium logging | Network-layer attack prevention and visibility |

### 3.8 Key Security Principles Demonstrated

**Defense in Depth:** Multiple independent security layers ensure that if one control fails or is bypassed, others prevent compromise. SSH hardening eliminates password based attacks, while audit logging detects unauthorized file modifications and firewall rate limiting slows connection based attacks.

**Risk-Based Prioritization:** Security hardening focused on high-impact controls: disabling password authentication eliminates brute force attacks entirely, while preventing root login forces privilege escalation through sudo (creating an audit trail). Non-standard ports and rate limiting reduce automated attack noise which improves the signal-to-noise ratio in security logs.

**Security Monitoring and Response:** Firewall logging at medium level provides visibility into connection attempts and blocked traffic patterns. Explicit deny rules for insecure protocols enable detection of reconnaissance activity and misconfigured applications attempting insecure connections.

**Operational Security Awareness:** Security requires analytical judgment, not blindy depending on automated tools. For example, rkhunter's alert on a systemd backup file required investigation to distinguish between false positives and genuine threats, demonstrating that effective security operations balance automation with human analysis.

---

## Phase 4: Automated Intrusion Prevention with Fail2Ban

### 4.1 The Need for Automated Response

In the previous phases, I established **detection** capabilities (Snort IDS, audit logging, firewall logging) and **prevention** controls (SSH hardening, firewall rules) but these were largely static defenses. In phase 4, I implemented **dynamic threat response** with fail2ban which automatically blocks attackers based on behavioral patterns detected in logs.

**The security gap Fail2Ban addresses:**
- Firewall rate limiting slows attacks but doesn't permanently block persistent attackers
- Snort detects attacks but requires manual intervention
- Audit logs provide evidence but don't stop ongoing attacks

Fail2Ban bridges the gap between **detection and response** which creates an automated incident response system.

### 4.2 Installing and Configuring Fail2Ban; SSH jail:**
```bash
sudo apt install fail2ban -y
sudo systemctl status fail2ban
sudo nano /etc/fail2ban/jail.local
```

![Fail2Ban Rule Config](screenshots/phase4/fail2ban_rule_config.png)

**Why these settings matter:**

- **`bantime = 600`**: Bans last 10 minutes: long enough to frustrate automated attacks, short enough that a legitimate user who mistypes their password isn't locked out for too long. It also gives security monitoring systems time to correlate patterns; if the same IP gets banned multiple times, that's a signal for escalated response.

- **`findtime = 300` + `maxretry = 3`**: If 3 failed authentication attempts occur within 5 minutes, it triggers a ban. This catches both fast and slow attacks. UFW's rate limiting handles rapid connections (6 in 30 seconds), but Fail2Ban can also catch the slower, more patient attacks that space out attempts to avoid rate limits.

- **`banaction = ufw`**: Fail2Ban adds rules directly to UFW, creating a unified firewall policy rather than managing a separate iptables chain


**Defense-in-depth with layered thresholds:**
1. **Firewall rate limiting**: 6 connections per 30 seconds (network layer)
2. **Fail2Ban**: 3 failed auth attempts per 5 minutes (application layer)
3. **SSH MaxAuthTries**: 3 attempts per connection (session layer)

Each layer integrates to catch both rapid automated attacks and slower, more sophisticated brute force attempts.

### 4.3 Verifying Fail2Ban Operation

**Checking jail status before attack simulation:**
```bash
sudo fail2ban-client status
sudo fail2ban-client status sshd
```

![Fail2Ban Active](screenshots/phase4/fail2ban_active.png)

Initial state shows:
- 1 jail configured (sshd)
- 0 currently failed connections
- 0 total failed attempts
- 0 currently banned IPs
- Empty banned IP list

### 4.4 Live Attack Simulation and Response

I simulated an SSH brute force attack from my Kali machine to watch how all the layers respond together:
```bash
for i in {1..6}; do ssh -p 2222 -o ConnectTimeout=2 -o PubKeyAuthentication=no user@10.0.2.8; done
```
![IDS IPS Integration Test](screenshots/phase4/ids_ips_integration_test.png)

This split-screen capture shows the complete defense response in real-time:

**Upper left (Kali attacker):** My attack attempts failing with "Permission denied (publickey,password)" because SSH is configured for key-only authentication. The final attempt gets "Connection refused"; that's when the firewall ban kicked in.

**Upper right (Snort detection):** Snort immediately detected the pattern and generated an alert: "Possible SSH Brute Force Attempt" from 10.0.2.15 to port 2222. This happened within seconds of the attack starting.

**Lower left (Fail2Ban status):** Running `sudo fail2ban-client status sshd` shows the jail caught 5 total failed attempts and banned IP 10.0.2.15. You can see "Currently banned: 1" and "Banned IP list: 10.0.2.15".

**Lower right (UFW firewall):** The `ufw status numbered` output shows a new rule was automatically added: `[1] Anywhere REJECT IN 10.0.2.15 # by Fail2Ban after 3 attempts against sshd`. This rule now sits at the top of my firewall, blocking all traffic from that IP before it even reaches SSH.

**What happened:** As I launched the attack, Fail2Ban monitors `/var/log/auth.log` in real-time. After detecting the pattern of failed authentication attempts, it executed the ban by calling `ufw insert 1 deny from 10.0.2.15`. This demonstrates automated security response without manual intervention. Without Fail2Ban, I could have kept trying forever (just slowly to avoid rate limits). With it, I'm automatically cut off after showing clear malicious intent.


### 4.5 Post System Hardening: The Complete Picture

**Services before hardening (14 running):** Shown in phase1

**Services after hardening (16 running):**

![Post Hardening Network Services](screenshots/phase4/post_hardening_network_services.png)

**What changed:**

**Removed:**
- **multipathd.service** (Device-Mapper Multipath Device Controller) - Designed for enterprise storage environments with multiple physical paths to storage devices (SAN/fiber channel redundancy). Unnecessary for single-disk VM, removed to demonstrate reducing attack surface by removing services that are not in use.

**Added:**
- **auditd.service** - Monitors /etc/passwd, /etc/shadow, and /etc/ssh/sshd_config for modifications, creating forensic trails if attackers attempt to create backdoor accounts or re-enable password authentication.

- **fail2ban.service** - Automated intrusion prevention monitoring authentication logs in real-time, automatically blocking malicious IPs.

- **postfix@-.service** - Mail transport agent enabling Fail2Ban email alerts (configured with destemail = ralzchrist@gmail.com). Without this, Fail2Ban can't send ban notifications.

- **networkd-dispatcher.service** - Event handler for systemd-networkd that responds to network state changes (interfaces up/down, IP changes, route modifications). Needed because UFW and Fail2Ban dynamically modify firewall rules, requiring proper handling of network configuration changes.


---

### 4.6 What This Project Demonstrates

**Defense in depth works:** During the attack simulation, multiple independent layers activated—SSH rejected authentication, Snort detected the pattern, , Fail2Ban analyzed behavior, and UFW blocked the IP. An attacker must defeat all layers simultaneously.

**Automation is essential:** From attack detection to blocking happened in under 5 seconds. Fail2Ban processes logs and executes responses faster than any human operator, reducing Mean Time to Respond (MTTR) from minutes to seconds.

**Detection alone isn't enough:** Snort provides visibility, but without Fail2Ban's automated response, it just creates work queues requiring manual intervention. Integration between detection and response tools creates effective defense.

**Security requires trade-offs:** Ten-minute bans disrupt automated attacks while preventing permanent legitimate user lockouts. REJECT actions prioritize performance over stealth. Non-standard ports reduce noise but add complexity. Understanding these trade-offs enables risk-based security decisions.

---

## Project Conclusion

This project implemented comprehensive endpoint security with three distinct layers:

**Prevention:** SSH hardening (key-only auth, root login disabled, port 2222, rate limiting), UFW firewall (default-deny, explicit allows, medium logging), automatic security patching, strong password policy.

**Detection:** Snort IDS (port scanning, SSH brute force, ICMP flooding rules), auditd (critical file monitoring), rkhunter (rootkit detection), UFW logging.

**Response:** Fail2Ban (automated IP blocking based on authentication patterns), integrated detection-to-response pipeline.

### Key Insights

**Layered security prevents compromise:** Individual controls can be bypassed, but it is more difficult to defeat multiple security layers simultaneously. 

**Automation enables scale:** Manual monitoring can't process modern log volumes. Automated tools respond to threats faster than human operators while reducing alert fatigue.

**Integration creates defense:** Snort detection alone requires manual response. Combined with Fail2Ban's automation, it creates a complete detect-and-respond pipeline.

**Trade-offs are inherent:** Every security control has operational impact. It is important to understand these trade-offs—like 10-minute bans versus permanent blocks because it enables appropriate risk-based decisions for the operating environment.
