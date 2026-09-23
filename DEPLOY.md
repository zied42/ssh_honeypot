# 🚀 Safe Deployment Guide for SSH Honeypot

This document provides step-by-step security hardening and deployment instructions for hosting the SSH honeypot on a public VPS for 2-4 weeks to capture live attacker data safely.

---

## ⚠️ Prerequisites & Threat Model Safety Rules

> [!CAUTION]
> **Use a Standalone VPS**: Never deploy this honeypot on your personal computer, home network, or production infrastructure. Use a dedicated low-cost VPS (DigitalOcean, Hetzner, Linode, AWS EC2, etc.) isolated from sensitive networks.

1. **Zero Outbound Access**: The honeypot container is configured with `internal: true` network boundaries. Under no circumstances should the honeypot make outbound network requests or download external binaries.
2. **100% Emulated Filesystem**: All commands and files live in memory. Attacker commands like `wget` and `curl` only log URLs as IOCs.

---

## Step 1: Shift Real Host SSH Port

Before binding the honeypot to public port `22`, move your VPS host SSH daemon to a high port (e.g. `22222`).

1. Edit SSH config on host:
   ```bash
   sudo nano /etc/ssh/sshd_config
   ```
2. Change `Port 22` to `Port 22222`:
   ```text
   Port 22222
   ```
3. Restart SSH service:
   ```bash
   sudo systemctl restart ssh
   ```
4. Test connecting in a **new terminal window** before closing current session:
   ```bash
   ssh -p 22222 user@<VPS_IP>
   ```

---

## Step 2: Firewall Configuration & Docker UFW Warning

> [!WARNING]
> Docker modifies `iptables` rules directly and **bypasses UFW default blocking**. To control traffic safely, use your cloud provider's external firewall (DigitalOcean Security Groups, AWS Security Groups) or configure the `DOCKER-USER` iptables chain.

### Cloud Provider Firewall Settings
- **Inbound Rules**:
  - Allow TCP `22222` (Host SSH admin access)
  - Allow TCP `22` (Public Honeypot port)
  - Allow TCP `5000` (Optional: Web Dashboard, restricted to your admin IP)
- **Outbound Rules**:
  - Block or restrict outbound connections from the honeypot host.

---

## Step 3: Launch Container via Docker Compose

1. Clone or upload the honeypot repository to `/opt/ssh_honeypot`.
2. Build and start the service:
   ```bash
   cd /opt/ssh_honeypot
   docker-compose up -d --build
   ```
3. Verify status:
   ```bash
   docker-compose ps
   docker-compose logs -f
   ```

---

## Step 4: Automated Daily Log Backup Strategy

To ensure attacker data is preserved across container restarts or host maintenance, set up a daily cron job to back up `data/logs`.

```bash
sudo crontab -e
```

Add daily backup job at 02:00 UTC:
```cron
0 2 * * * tar -czf /var/backups/honeypot_logs_$(date +\%F).tar.gz -C /opt/ssh_honeypot/data logs/
```

---

## Step 5: Generating Analytics & Threat Intelligence Reports

To generate comprehensive JSON and Markdown reports at any point during collection:

```bash
docker-compose exec ssh_honeypot python analyzer/analyzer.py --hours 720
```

Or run locally on host using Python 3:
```bash
python3 analyzer/analyzer.py --log-dir data/logs --output analytics_report.json --markdown analytics_report.md
```

Access the Markdown summary in `analytics_report.md` for write-up publishing.
