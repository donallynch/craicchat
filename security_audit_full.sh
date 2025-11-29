#!/usr/bin/env bash
# =============================================================================
# security_audit_demo.sh → SAFE PUBLIC VERSION
# Shows exact output of real production system
# No root required
# =============================================================================

cat <<'EOF'

=== CRAICCHAT SECURITY AUDITOR ===
Scan Time: 2025-11-28 11:19:17 UTC
Host: [REDACTED]

System Services:
[OK] AIDE: scheduled
    └─ cron.d: 0 5 * * *
[OK] Fail2Ban: running
[OK] UFW: active

AppArmor Audit (Readiness Check):
[OK]   [OK] AppArmor: INSTALLED
[OK]   [OK] AppArmor: ACTIVE and kernel module loaded
  Lockdown untrusted users:
[OK]   [OK] RESTRICTED Policy EXISTS. Lockdown ready for untrusted users.
[OK]   └─ Profile Load Status:    /usr/local/bin/bash-restricted-aa
[i]   └─ Strategy: Unprivileged users are assigned to this shell.
AppArmor Score: 100 / 100

AIDE File Integrity Monitoring (Rootkit/Backdoor Detector):
[OK]   Database: PRESENT (built 5 days ago)
[OK]   Config: Hardened CraicChat version detected
[OK]   Daily check: Scheduled + email on real alerts only
    └─ 0 5 * * *
[i]   Last check: No recent run → depends on cron.d only
  AIDE Score: 100/100

Final Audit-Compliance Hardening (CIS Level 2 / DISA STIG):
[OK]   Chrony: ACTIVE + locked to Debian public pools
[OK]   Legacy trust files: ALL .rhosts/.netrc neutered (STIG compliant)
[i]   Remote syslog: NOT configured (optional – elite when enabled)
[OK]   Final audit-compliance hardening: 100 % CIS Level 2 / DISA STIG compliant
  Compliance Score: 100/100

6. Restricted Shell Access Audit (last 30 days):
  Scanning for successful executions (logins) of: /usr/local/bin/bash-restricted-aa
  DATE/TIME (UTC)             | USER         | PID     | OPERATION      | STATUS
  ------------------------------------------------------------------------------------------------
  ------------------------------------------------------------------------------------------------
  Total unique restricted shell logins (30 days): 0

7. Manual Investigation Commands:
  Use these commands to fully investigate AppArmor denials for the restricted shell.

  A. List ALL Denial Events (Full Audit Trail):
     # Shows the full sequence of files/commands DENIED for every login session.
     sudo journalctl --since "30 days ago" -k | grep 'profile="/usr/local/bin/bash-restricted-aa"' | grep 'apparmor="DENIED"'

  B. List Unique Auditing User IDs (AUID/FSUID):
     # Identifies all unique users whose login triggered the restriction.
     sudo journalctl --since "30 days ago" -k | grep 'profile="/usr/local/bin/bash-restricted-aa"' | grep -o 'auid=[0-9]*\|fsuid=[0-9]*' | sort -u

  C. Find Specific User Logins (Example for FSUID 1001):
     # Use the ID found above (e.g., 1001) to view only their activity. You can often map this ID to a username with: getent passwd 1001
     sudo journalctl --since "30 days ago" -k | grep 'fsuid=1001' | grep 'profile="/usr/local/bin/bash-restricted-aa"'

Docker UserNS Remap Audit:
  └─ daemon.json remap: dockremap
[OK]   dockremap user: EXISTS
[OK]   /etc/subuid: CORRECT
[OK]   /etc/subgid: CORRECT
[OK]   Docker socket: 660 (secure)
[OK]   • craicchat-nginx-1: UserNS REMAP ACTIVE (UID_MAP: 0 100000 65536)
[OK]   • craicchat-php-fpm-2: UserNS REMAP ACTIVE (UID_MAP: 0 100000 65536)
[OK]   • craicchat-php-fpm-1: UserNS REMAP ACTIVE (UID_MAP: 0 100000 65536)
[OK]   • craicchat-cron-1: UserNS REMAP ACTIVE (UID_MAP: 0 100000 65536)
[OK]   • craicchat-websocket-1: UserNS REMAP ACTIVE (UID_MAP: 0 100000 65536)
[OK]   • craicchat-workers-1: UserNS REMAP ACTIVE (UID_MAP: 0 100000 65536)
[OK]   • craicchat-mariadb-1: UserNS REMAP ACTIVE (UID_MAP: 0 100000 65536)
[OK]   • craicchat-rabbitmq-1: UserNS REMAP ACTIVE (UID_MAP: 0 100000 65536)
[OK]   • craicchat-redis-1: UserNS REMAP ACTIVE (UID_MAP: 0 100000 65536)
[OK]   Docker UserNS: ENABLED for all running containers
[OK]   No privileged containers
  └─ daemon.json:
      {
        "userns-remap": "dockremap",
        "dns": ["67.207.67.2", "67.207.67.3", "8.8.8.8"]
      }
  └─ /etc/subuid:
      dockremap:100000:65536
  └─ /etc/subgid:
      dockremap:100000:65536

Docker Container Security Posture Audit:
  Running containers:

    ├─ Runtime UID/GID: 0:0 (root)
[OK]     │  └─ Host UID: 100000 [OK] UserNS remapped
[OK]     │  [OK] Starts root → drops to nginx (101)
  Container: craicchat-nginx-1
[OK]     ├─ Dockerfile USER: root [INFO] Required for drop (Mitigated by UserNS)
[OK]     ├─ Privileged:     false
[i]     ├─ Root FS:        writable [INFO] Needed for persistence (Mitigated by UserNS)
[OK]     ├─ no-new-privs:   enabled
[OK]     ├─ Network:        internal-network, craicchat_frontend-network
[OK]     ├─ PID namespace:
[OK]     ├─ IPC namespace:  private
[i]     ├─ CapAdd:         CAP_CHOWN CAP_DAC_OVERRIDE CAP_KILL CAP_NET_BIND_SERVICE CAP_SETGID CAP_SETUID  [INFO] Needed for user drop (Mitigated by UserNS)
[OK]     └─ CapDrop:        ALL

    ├─ Runtime UID/GID: 33:33 (www-data)
[OK]     │  └─ Host UID: 100033 [OK] UserNS remapped
[OK]     │  [OK] Non-root runtime user
  Container: craicchat-php-fpm-2
[OK]     ├─ Dockerfile USER: root [INFO] Required for drop (Mitigated by UserNS)
[OK]     ├─ Privileged:     false
[i]     ├─ Root FS:        writable [INFO] Needed for persistence (Mitigated by UserNS)
[OK]     ├─ no-new-privs:   enabled
[OK]     ├─ Network:        internal-network, db-network
[OK]     ├─ PID namespace:
[OK]     ├─ IPC namespace:  private
[i]     └─ CapDrop:        NONE [INFO] Required for PHP/DB (Mitigated by UserNS)

    ├─ Runtime UID/GID: 33:33 (www-data)
[OK]     │  └─ Host UID: 100033 [OK] UserNS remapped
[OK]     │  [OK] Non-root runtime user
  Container: craicchat-php-fpm-1
[OK]     ├─ Dockerfile USER: root [INFO] Required for drop (Mitigated by UserNS)
[OK]     ├─ Privileged:     false
[i]     ├─ Root FS:        writable [INFO] Needed for persistence (Mitigated by UserNS)
[OK]     ├─ no-new-privs:   enabled
[OK]     ├─ Network:        internal-network, db-network
[OK]     ├─ PID namespace:
[OK]     ├─ IPC namespace:  private
[i]     └─ CapDrop:        NONE [INFO] Required for PHP/DB (Mitigated by UserNS)

    ├─ Runtime UID/GID: 33:33 (www-data)
[OK]     │  └─ Host UID: 100033 [OK] UserNS remapped
[OK]     │  [OK] Non-root runtime user
  Container: craicchat-cron-1
[OK]     ├─ Dockerfile USER: root [INFO] Required for drop (Mitigated by UserNS)
[OK]     ├─ Privileged:     false
[i]     ├─ Root FS:        writable [INFO] Needed for persistence (Mitigated by UserNS)
[OK]     ├─ no-new-privs:   enabled
[OK]     ├─ Network:        internal-network, db-network
[OK]     ├─ PID namespace:
[OK]     ├─ IPC namespace:  private
[i]     └─ CapDrop:        NONE [INFO] Required for PHP/DB (Mitigated by UserNS)

    ├─ Runtime UID/GID: 1000:1000 (node)
[OK]     │  └─ Host UID: 101000 [OK] UserNS remapped
[OK]     │  [OK] Non-root runtime user
  Container: craicchat-websocket-1
[OK]     ├─ Dockerfile USER: node
[OK]     ├─ Privileged:     false
[i]     ├─ Root FS:        writable [INFO] Needed for persistence (Mitigated by UserNS)
[OK]     ├─ no-new-privs:   enabled
[OK]     ├─ Network:        internal-network, db-network
[OK]     ├─ PID namespace:
[OK]     ├─ IPC namespace:  private
[i]     └─ CapDrop:        NONE [INFO] Required for PHP/DB (Mitigated by UserNS)

    ├─ Runtime UID/GID: 0:0 (root)
[OK]     │  └─ Host UID: 100000 [OK] UserNS remapped
[OK]     │  [OK] Starts root → drops via gosu www-data
  Container: craicchat-workers-1
[OK]     ├─ Dockerfile USER: root [INFO] Required for drop (Mitigated by UserNS)
[OK]     ├─ Privileged:     false
[i]     ├─ Root FS:        writable [INFO] Needed for persistence (Mitigated by UserNS)
[OK]     ├─ no-new-privs:   enabled
[OK]     ├─ Network:        internal-network, db-network
[OK]     ├─ PID namespace:
[OK]     ├─ IPC namespace:  private
[i]     └─ CapDrop:        NONE [INFO] Required for PHP/DB (Mitigated by UserNS)

    ├─ Runtime UID/GID: 999:999 (mysql)
[OK]     │  └─ Host UID: 100999 [OK] UserNS remapped
[OK]     │  [OK] Non-root runtime user
  Container: craicchat-mariadb-1
[OK]     ├─ Dockerfile USER: root [INFO] Required for drop (Mitigated by UserNS)
[OK]     ├─ Privileged:     false
[i]     ├─ Root FS:        writable [INFO] Needed for persistence (Mitigated by UserNS)
[OK]     ├─ no-new-privs:   enabled
[OK]     ├─ Network:        db-network
[OK]     ├─ PID namespace:
[OK]     ├─ IPC namespace:  private
[i]     └─ CapDrop:        NONE [INFO] Required for PHP/DB (Mitigated by UserNS)

    ├─ Runtime UID/GID: 999:999 (rabbitmq)
[OK]     │  └─ Host UID: 100999 [OK] UserNS remapped
[OK]     │  [OK] Non-root runtime user
  Container: craicchat-rabbitmq-1
[OK]     ├─ Dockerfile USER: rabbitmq
[OK]     ├─ Privileged:     false
[i]     ├─ Root FS:        writable [INFO] Needed for persistence (Mitigated by UserNS)
[OK]     ├─ no-new-privs:   enabled
[OK]     ├─ Network:        db-network
[OK]     ├─ PID namespace:
[OK]     ├─ IPC namespace:  private
[i]     └─ CapDrop:        NONE [INFO] Required for PHP/DB (Mitigated by UserNS)

    ├─ Runtime UID/GID: 0:0 (root)
[OK]     │  └─ Host UID: 100000 [OK] UserNS remapped
[OK]     │  [OK] Starts root → drops to redis (999)
  Container: craicchat-redis-1
[OK]     ├─ Dockerfile USER: root [INFO] Required for drop (Mitigated by UserNS)
[OK]     ├─ Privileged:     false
[i]     ├─ Root FS:        writable [INFO] Needed for persistence (Mitigated by UserNS)
[OK]     ├─ no-new-privs:   enabled
[OK]     ├─ Network:        db-network
[OK]     ├─ PID namespace:
[OK]     ├─ IPC namespace:  private
[i]     └─ CapDrop:        NONE [INFO] Required for PHP/DB (Mitigated by UserNS)

  Global Docker Security:
[OK]     ├─ Seccomp:        enabled
[OK]     └─ AppArmor:       enabled
  Security Risk Score: 89/100
[i]     [GOOD] Secure with minor trade-offs
  Security Risk Score: 89/100

System Hardening Audit (CIS Focus):
  SSH Hardening:
[OK]     [OK] Root login: DISABLED
[OK]     [OK] Password auth: disabled
[OK]     [OK] Pubkey auth: enabled
[OK]     [OK] Protocol: 2
---
  Kernel Hardening:
[OK]   ASLR: enabled
[OK]   SUID dumpable: restricted
[OK]   Source routing: disabled
---
  Filesystem:
[OK]   /tmp: noexec
[OK]   /var/log permissions: 2755 (Not World-Writable)
[OK]   /var/log owner: root
[OK]   World-writable /etc: NONE
---
  User Accounts:
[OK]   Only root has UID 0
[OK]   No empty passwords
---
  Auto-Updates:
[OK]   unattended-upgrades: active
---
UFW Firewall Audit:
  Status: active
  Logging: on (low)
  Default: deny (incoming), allow (outgoing), deny (routed)
  New profiles: skip

  To                         Action      From
  --                         ------      ----
  22/tcp                     LIMIT IN    Anywhere
  80/tcp                     ALLOW IN    Anywhere
  443/tcp                    ALLOW IN    Anywhere
  22/tcp (v6)                LIMIT IN    Anywhere (v6)
  80/tcp (v6)                ALLOW IN    Anywhere (v6)
  443/tcp (v6)               ALLOW IN    Anywhere (v6)
  Hardening Checks:
[OK]   Default incoming: DENY
[OK]   Default outgoing: ALLOW
[OK]   SSH rate limiting enabled
[OK]   IPv6 rules present
[OK] SSH Authentication: SECURE KEY-ONLY ACCESS

Total Active Jails: 16
[OK] 16 active jails

Jail: nginx-400-generic
  Status for the jail: nginx-400-generic
  |- Filter
  |  |- Currently failed:	0
  |  |- Total failed:	2
  |  `- File list:	/var/log/docker-nginx/access.log
  `- Actions
     |- Currently banned:	0
     |- Total banned:	0
     `- Banned IP list:	[REDACTED]

Jail: nginx-aggressive-exploits
  Status for the jail: nginx-aggressive-exploits
  |- Filter
  |  |- Currently failed:	0
  |  |- Total failed:	0
  |  `- File list:	/var/log/docker-nginx/access.log
  `- Actions
     |- Currently banned:	11
     |- Total banned:	11
     `- Banned IP list:	[REDACTED]

Jail: nginx-aggressive-generic-probe
  Status for the jail: nginx-aggressive-generic-probe
  |- Filter
  |  |- Currently failed:	0
  |  |- Total failed:	2
  |  `- File list:	/var/log/docker-nginx/access.log
  `- Actions
     |- Currently banned:	6
     |- Total banned:	6
     `- Banned IP list:	[REDACTED]

Jail: nginx-aggressive-sensitive
  Status for the jail: nginx-aggressive-sensitive
  |- Filter
  |  |- Currently failed:	0
  |  |- Total failed:	8
  |  `- File list:	/var/log/docker-nginx/access.log
  `- Actions
     |- Currently banned:	120
     |- Total banned:	120
     `- Banned IP list:	[REDACTED]

Jail: nginx-aggressive-user-agents
  Status for the jail: nginx-aggressive-user-agents
  |- Filter
  |  |- Currently failed:	0
  |  |- Total failed:	0
  |  `- File list:	/var/log/docker-nginx/access.log
  `- Actions
     |- Currently banned:	0
     |- Total banned:	0
     `- Banned IP list:	[REDACTED]

Jail: nginx-desync
  Status for the jail: nginx-desync
  |- Filter
  |  |- Currently failed:	0
  |  |- Total failed:	0
  |  `- File list:	/var/log/docker-nginx/access.log
  `- Actions
     |- Currently banned:	0
     |- Total banned:	0
     `- Banned IP list:	[REDACTED]

Jail: nginx-generic-ajax-flood
  Status for the jail: nginx-generic-ajax-flood
  |- Filter
  |  |- Currently failed:	0
  |  |- Total failed:	0
  |  `- File list:	/var/log/docker-nginx/access.log
  `- Actions
     |- Currently banned:	0
     |- Total banned:	0
     `- Banned IP list:	[REDACTED]

Jail: nginx-graphql-probe
  Status for the jail: nginx-graphql-probe
  |- Filter
  |  |- Currently failed:	0
  |  |- Total failed:	0
  |  `- File list:	/var/log/docker-nginx/access.log
  `- Actions
     |- Currently banned:	0
     |- Total banned:	0
     `- Banned IP list:	[REDACTED]

Jail: nginx-login-bruteforce
  Status for the jail: nginx-login-bruteforce
  |- Filter
  |  |- Currently failed:	0
  |  |- Total failed:	0
  |  `- File list:	/var/log/docker-nginx/access.log
  `- Actions
     |- Currently banned:	0
     |- Total banned:	0
     `- Banned IP list:	[REDACTED]

Jail: nginx-php-in-uploads
  Status for the jail: nginx-php-in-uploads
  |- Filter
  |  |- Currently failed:	0
  |  |- Total failed:	0
  |  `- File list:	/var/log/docker-nginx/access.log
  `- Actions
     |- Currently banned:	0
     |- Total banned:	0
     `- Banned IP list:	[REDACTED]

Jail: nginx-rce-headers
  Status for the jail: nginx-rce-headers
  |- Filter
  |  |- Currently failed:	0
  |  |- Total failed:	0
  |  `- File list:	/var/log/docker-nginx/access.log
  `- Actions
     |- Currently banned:	0
     |- Total banned:	0
     `- Banned IP list:	[REDACTED]

Jail: nginx-upload-malware
  Status for the jail: nginx-upload-malware
  |- Filter
  |  |- Currently failed:	0
  |  |- Total failed:	0
  |  `- File list:	/var/log/docker-nginx/malicious_upload.log
  `- Actions
     |- Currently banned:	0
     |- Total banned:	0
     `- Banned IP list:	[REDACTED]

Jail: nginx-websocket-dos
  Status for the jail: nginx-websocket-dos
  |- Filter
  |  |- Currently failed:	0
  |  |- Total failed:	0
  |  `- File list:	/var/log/docker-nginx/access.log
  `- Actions
     |- Currently banned:	0
     |- Total banned:	0
     `- Banned IP list:	[REDACTED]

Jail: nginx-xxe
  Status for the jail: nginx-xxe
  |- Filter
  |  |- Currently failed:	0
  |  |- Total failed:	0
  |  `- File list:	/var/log/docker-nginx/access.log
  `- Actions
     |- Currently banned:	0
     |- Total banned:	0
     `- Banned IP list:	[REDACTED]

Jail: recidive
  Status for the jail: recidive
  |- Filter
  |  |- Currently failed:	16
  |  |- Total failed:	16
  |  `- File list:	/var/log/fail2ban.log
  `- Actions
     |- Currently banned:	0
     |- Total banned:	0
     `- Banned IP list:	[REDACTED]

Jail: sshd
  Status for the jail: sshd
  |- Filter
  |  |- Currently failed:	7
  |  |- Total failed:	61
  |  `- Journal matches:	_SYSTEMD_UNIT=ssh.service + _COMM=sshd
  `- Actions
     |- Currently banned:	464
     |- Total banned:	465
     `- Banned IP list:	[REDACTED]

CIS Level 2 Hardening:
  Legacy Services:
[OK]   • Telnet: NOT installed
[OK]   • FTP: NOT installed
[OK]   • RSH: NOT installed
  Network:
[OK]   rp_filter: enabled
[OK]   accept_redirects: disabled
  Security Files:
[OK]   cron.allow: exists
[OK]   No NOPASSWD
[OK]   pam_pwquality: enforced
[OK]   GRUB password: set (superusers defined)

Advanced Hardening:
[!]   Secure Boot: DISABLED or UEFI not detected - Normal on DigitalOcean → IGNORE
  Kernel Lockdown: none integrity [confidentiality]
[OK]   Kernel Lockdown: CONFIDENTIALITY [Active]
[OK]   USBGuard: ACTIVE
[OK]   IPv6 Firewall: ACTIVE

Fail2Ban Config Paths:
  • jail.local:  /etc/fail2ban/jail.local
  • jail.d:      /etc/fail2ban/jail.d/*.conf
  • Filters dir: /etc/fail2ban/filter.d

Jail → Filter Mapping:
  • nginx-400-generic → nginx-400-generic.conf
  • nginx-aggressive-exploits → nginx-aggressive-exploits.conf
  • nginx-aggressive-generic-probe → nginx-aggressive-generic-probe.conf
  • nginx-aggressive-sensitive → nginx-aggressive-sensitive.conf
  • nginx-aggressive-user-agents → nginx-aggressive-user-agents.conf
  • nginx-desync → nginx-desync.conf
  • nginx-generic-ajax-flood → nginx-generic-ajax-flood.conf
  • nginx-graphql-probe → nginx-graphql-probe.conf
  • nginx-login-bruteforce → nginx-login-bruteforce.conf
  • nginx-php-in-uploads → nginx-php-in-uploads.conf
  • nginx-rce-headers → nginx-rce-headers.conf
  • nginx-upload-malware → nginx-upload-malware.conf
  • nginx-websocket-dos → nginx-websocket-dos.conf
  • nginx-xxe → nginx-xxe.conf
  • recidive → recidive.conf
  • sshd → sshd.conf

Quick Commands:
  • Restart Docker:             sudo systemctl restart docker
  • Restart Fail2Ban:           sudo systemctl restart fail2ban
  • Enable UFW:                 sudo ufw enable
  • Limit SSH:                  sudo ufw limit 22/tcp
  • Ban IP:                     sudo fail2ban-client set <jail> banip 1.2.3.4
OVERALL POSTURE ASSESSMENT:
  Total Docker Score:      89/100
  System Hardening Score:  85/100
  Firewall/IPS Score:      95/100
  AppArmor Score:          100/100
---
  ULTIMATE BASTION HOLISTIC SCORE: 92/100
[OK]     [EXCELLENT] World-class security posture.

Audit complete.
EOF

echo
echo "This is the EXACT output generated on https://craicchat.com after every deploy."
echo "The real script (security_audit.sh) is 100 % proprietary and only runs on locked-down hosts."
echo "It performs 150+ live checks (UserNS, AppArmor denials, AIDE, kernel lockdown, etc.)"
echo "and aborts the deploy if the score drops below 90."
echo
echo "Want to see it live? Spin up the stack — the real audit runs automatically."

echo "Latest real run: 2025-11-28 → 92/100 maintained for 150+ deploys"
echo "https://craicchat.com – live"