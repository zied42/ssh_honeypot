# SSH Honeypot

A Python-based SSH honeypot for detecting and logging malicious SSH login attempts and commands.

## Features

- Emulated SSH server with fake filesystem
- Command logging and attack detection
- Password capture from failed sudo attempts
- Canary file detection
- Severity-based alerting

## Installation
```bash
pip install -r requirements.txt
```

## Usage
```bash
python main.py
```

The honeypot will start on `0.0.0.0:2222` by default.

## Configuration

Edit `config/settings.py` to customize:
- Valid credentials
- Listening host/port
- Logging settings
- System information

## Logs

- `logs/audits.log` - Connection and session logs
- `logs/cmd_audits.log` - All executed commands
- `logs/alerts.log` - Security alerts and canary triggers

## Security Warning

**DO NOT** expose this honeypot directly to the internet without proper isolation and monitoring. Run in a contained environment.