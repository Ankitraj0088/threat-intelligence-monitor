# Deployment and isolation

Run the sensor on a dedicated disposable VPS/VM or isolated network segment. Never place it on a personal laptop/home LAN alongside sensitive systems.

1. Patch the host.
2. Protect the real admin SSH service before using port 22 for the decoy.
3. Use SSH keys for administration.
4. Keep dashboard port 5000 on 127.0.0.1.
5. Restrict outbound traffic where practical.
6. Configure firewall/security-group rules for only intended decoy ports and admin access.
7. Store SMTP and dashboard secrets outside the repository.
8. Monitor disk usage and back up SQLite if needed.
9. Never execute captured samples.
10. Never scan, probe, retaliate against, or connect back to source IPs.

## systemd
```bash
sudo useradd --system --home /opt/ankit-honeypot-threat-monitor honeypot
sudo cp -r . /opt/ankit-honeypot-threat-monitor
sudo chown -R honeypot:honeypot /opt/ankit-honeypot-threat-monitor
python3 -m venv /opt/ankit-honeypot-threat-monitor/.venv
/opt/ankit-honeypot-threat-monitor/.venv/bin/pip install -r /opt/ankit-honeypot-threat-monitor/requirements.txt
sudo cp systemd/ankit-honeypot.service /etc/systemd/system/
sudo cp .env.example /etc/ankit-honeypot.env
sudo chmod 600 /etc/ankit-honeypot.env
sudo systemctl daemon-reload
sudo systemctl enable --now ankit-honeypot
```

Use `systemctl status ankit-honeypot` and `journalctl -u ankit-honeypot -f` to monitor it.
