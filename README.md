# ThreatSentinel

A defensive low-interaction SSH/Telnet/HTTP honeypot for an isolated VPS/VM. It records real incoming interactions, persists telemetry in SQLite, detects brute force/recon/signature activity, maps detections to MITRE ATT&CK, provides an SSE live dashboard, and can send cooldown-controlled email alerts.

**Safety:** SSH authentication always fails; no shell or command execution is exposed. Captured HTTP uploads are hashed/stored only and never executed. Do not deploy this beside production systems.

## Run locally
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env
python honeypot.py run
```
Dashboard: `http://127.0.0.1:5000`

Generate controlled traffic only against your own local sensor:
```bash
./generate_lab_traffic.sh
```

## Real deployment
Use a dedicated disposable Linux VPS/VM. Keep the real administrator SSH service separate from the fake SSH listener. Expose only the decoy ports you intentionally choose. Keep the dashboard on localhost and reach it through an SSH tunnel:
```bash
ssh -L 5000:127.0.0.1:5000 user@YOUR_VPS_IP
```
Then open `http://127.0.0.1:5000` locally.

The systemd unit restarts the sensor after failure and starts it on boot. For privileged ports (22/23/80), first protect/move the real management service and use the minimum Linux capability required by your deployment. Do not blindly put a fake SSH listener on port 22 while your real SSH daemon still uses it.

## Features
- Real incoming fake SSH/Telnet/HTTP interactions
- Persistent SQLite history across restarts/days
- Real-time SSE event/alert stream
- Attacker profiles and timelines through API
- Rule-based 0-100 explainable threat score
- MITRE ATT&CK: T1110, T1595, T1190, T1078
- Curated CVE/signature detection
- SHA-256 + entropy for captured HTTP payloads
- Masked credential display in dashboard
- Optional SMTP alerts with per-IP/per-alert cooldown
- 90-day configurable raw telemetry retention
- Docker and systemd deployment files
- No fake counts, fake intelligence, ML claims, or attacker-IP callbacks

## API
`/api/stats`, `/api/events`, `/api/alerts`, `/api/attackers`, `/api/signatures`, `/api/chart`, `/api/credentials`, `/api/samples`, `/events`, `/export.csv`

## Email
Set `ALERT_EMAIL_ENABLED=true`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `ALERT_TO`. Secrets belong in environment configuration, not source control.

## Limitations
This is a low-interaction honeypot, not a full OS/SSH emulator and not a replacement for Zeek/Suricata/SIEM. Threat scores are heuristics, not probabilities. Do not claim real-attacker statistics or detection precision until you have actually deployed it and collected evidence.
