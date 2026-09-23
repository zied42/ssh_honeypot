# 🚀 Production Deployment & Security Hardening Guide

This document provides step-by-step security hardening and production deployment instructions for hosting **Sentinel SSH Honeypot** on a public VPS for 2–4 weeks to capture real attacker data safely.

---

## ⚠️ Threat Model & Isolation Safety Rules

> [!CAUTION]
> **Deploy ONLY on an Isolated Standalone VPS**: Never host an active honeypot on your personal computer, home network, or production company infrastructure. Use a dedicated low-cost or free-tier VPS (Oracle Cloud Always Free, AWS Free Tier, DigitalOcean, Hetzner, Linode).

1. **Zero Outbound Network Traffic**: The honeypot Docker container runs with an isolated network bridge (`internal: true`). Attacker commands like `wget`, `curl`, and `tftp` only extract Indicators of Compromise (IOCs) into logs. No outbound connections leave the container.
2. **100% In-Memory Emulated Execution**: All files, directories, and command responses live strictly in memory. Attacker payloads are never executed on the host system or Python process.

---

## 🛡️ Step 1: Install & Configure Tailscale VPN (Management Protection)

Using **Tailscale VPN** removes your real host management SSH server from the public internet entirely.

### 1. Connect your Local Management Machine to Tailscale
Install Tailscale on your local computer from [tailscale.com/download](https://tailscale.com/download) and sign in. Note your local machine IP (`100.x.y.z`).

### 2. Install Tailscale on the Public VPS
SSH into your fresh VPS instance and run:

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
```

Authenticate by opening the printed URL in your browser. Once authorized, your VPS will join your private tailnet and receive its own Tailscale IP (e.g., `100.70.80.90`).

---

## 🔐 Step 2: Harden & Shift Real Host SSH (`sshd`)

> [!IMPORTANT]
> Keep your active SSH session open while performing this step. Test connecting in a **new terminal window** before closing the original connection!

1. Edit host SSH configuration:
   ```bash
   sudo nano /etc/ssh/sshd_config
   ```

2. Configure hardening parameters:
   ```text
   Port 22222
   ListenAddress 100.70.80.90     # Replace with your VPS Tailscale IP
   PasswordAuthentication no
   PermitRootLogin no
   PubkeyAuthentication yes
   ```

3. **Ubuntu 22.10+ Socket Activation Fix** (if applicable):
   On newer Ubuntu versions, systemd socket activation manages port 22 by default:
   ```bash
   sudo systemctl disable --now ssh.socket
   sudo systemctl enable --now ssh
   sudo systemctl restart ssh
   ```

4. **Test connecting over Tailscale in a new terminal**:
   ```bash
   ssh -p 22222 user@100.70.80.90
   ```

---

## 🧱 Step 3: Firewall Configuration & Docker UFW Notice

> [!WARNING]
> On Linux, Docker modifies `iptables` directly and **bypasses UFW default blocking**. To ensure administrative ports are never exposed publicly, bind specific ports to `127.0.0.1` or your Tailscale IP in `docker-compose.yml`.

### Cloud Provider External Firewall Settings (AWS / DigitalOcean / Oracle VCN)
Configure your cloud provider's external security group / firewall rules:

| Protocol | Port | Source | Purpose |
|---|---|---|---|
| **TCP** | `22` | `0.0.0.0/0` (Anywhere) | Public Honeypot (Captures Attackers) |
| **UDP** | `41641` | `0.0.0.0/0` (Anywhere) | Tailscale Encrypted VPN Tunnel |
| **TCP** | `22222` | VPN Subnet / Admin IP | Host SSH Admin Management |
| **TCP** | `5000` | VPN Subnet / Admin IP | Analytics Web Dashboard |

---

## 📦 Step 4: Clone & Launch Honeypot Container

1. Clone repository to `/opt/ssh_honeypot`:
   ```bash
   sudo git clone https://github.com/zied42/ssh_honeypot.git /opt/ssh_honeypot
   cd /opt/ssh_honeypot
   ```

2. Build and launch container in daemon mode:
   ```bash
   sudo docker-compose up -d --build
   ```

3. Verify status and monitor live logs:
   ```bash
   sudo docker-compose ps
   sudo docker-compose logs -f ssh_honeypot
   ```

---

## 💾 Step 5: Automated Daily Log Backup Strategy

Attacker telemetry is stored under `/opt/ssh_honeypot/data/logs`. To ensure data is preserved across container restarts or host updates, set up a daily root cron job:

```bash
sudo crontab -e
```

Add the following daily backup schedule (runs at 02:00 UTC):
```cron
0 2 * * * tar -czf /var/backups/honeypot_logs_$(date +\%F).tar.gz -C /opt/ssh_honeypot/data logs/
```

---

## 📊 Step 6: Generating Campaign Analytics & Threat Reports

Generate complete JSON and Markdown campaign reports for write-ups or SIEM analysis:

```bash
# Run analysis inside running container
sudo docker-compose exec ssh_honeypot python analyzer/analyzer.py --hours 720 --output data/report.json --markdown data/report.md
```

Or run directly on the host using Python 3:
```bash
python3 analyzer/analyzer.py --log-dir data/logs --output analytics_report.json --markdown analytics_report.md
```
