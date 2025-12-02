# Donal Lynch – Principal Platform & Security Engineer
**15 years experience | Ireland | EU Remote**  
github.com/donallynch | donal.lynch.msc@gmail.com | CV → [CV_Donal_Lynch.pdf](CV_Donal_Lynch.pdf)

### Current Project – CraicChat (2023–Present)
**Live**: https://craicchat.com · https://craicchat.ie

Solo-built, real-time, E2EE social & messaging platform in continuous production since Oct 2024 (Ireland · UK · EU · US users).

- 170+ consecutive zero-downtime production deploys
- Real-time Socket.IO + E2EE private messaging
- Stripe SCA + GDPR compliance
- Entire stack built, secured, and operated by one engineer

### Production Security Posture – Independently Verifiable
Automated bastion audit runs after **every deploy** → aborts if score < 90.  
**Latest (2025-11-28)** → **92/100 Automated Governance Score**

### Zero-Downtime Production Deploys
170+ consecutive zero-downtime deploys via automated canary rollouts.  
No Kubernetes, no paid tools — pure docker-compose + bash + nginx `resolve`.

→ Full process: [zero_downtime_deployments.txt](zero_downtime_deployments.txt)

### Landing page – live production (Nov 2025)
![CraicChat landing page – live production (November 2025)](craicchat.png)

<details>
<summary><strong>Click for full security posture summary (30 seconds)</strong></summary>

```text
CraicChat Production Security Posture – 2025-11-28
Automated Governance Score: 92/100
• Kernel lockdown = confidentiality (active)
• Docker UserNS remapping on all containers (no process ever real UID 0 on host)
• No privileged containers, seccomp + AppArmor + no-new-privs
• CIS L2 / DISA STIG compliance: 100%
• Fail2Ban: 16 jails, 600+ IPs permanently banned
• SSH: pubkey-only, root disabled, rate-limited
• AIDE + USBGuard default-deny
• Deploy aborted automatically if score drops below 90

→ Full audit script: security_audit_full.sh
→ Live site: https://craicchat.com
```
</details>