# TIGRESS – Threat Intelligence Grid for Android

Security monitoring framework for Android/Termux: WiFi anomaly detection, physical tamper detection, and ML-based threat analysis.

## Features
- WiFi scanning with new-BSSID and SSID-rule alerting
- Accelerometer-based tamper detection
- Isolation Forest anomaly detection (auto-trains on first run)
- Encrypted configuration (hardware-backed when available)
- Tamper-proof audit logging (hash chain + ECDSA signatures)
- Runtime file and process integrity monitoring
- Mutual TLS for dashboard communication
- Termux push notifications

## Limitations (Android 13+)
- `termux-wifi-scaninfo` returns cached data — scans may be stale
- Accelerometer sensor name is auto-detected per device
- ML models require a training pass before anomaly detection activates
- For background operation: use `termux-wake-lock` and keep Termux in the foreground

## Installation
```bash
pkg install python termux-api
pip install -r requirements.txt
bash scripts/harden.sh
```

## Usage
```bash
# Training mode — collect baseline data
bash scripts/tigress_launcher.sh --train

# Normal operation
bash scripts/tigress_launcher.sh

# Secure mode (verifies boot manifest before starting)
bash scripts/tigress_launcher.sh --secure

# Demo mode (no real sensors required)
bash scripts/tigress_launcher.sh --dummy
```

The dashboard listens on the host/port from the `server` section of
`config/config.yaml` (default `127.0.0.1:8080`).

## Dashboard API
The dashboard exposes read-only JSON endpoints:

| Endpoint | Description |
| -------- | ----------- |
| `GET /` | Status and sensor list |
| `GET /sensors` | Per-sensor status |
| `GET /health` | Liveness probe |
| `GET /detections` | Recent detections, newest first. Query params: `limit`, `min_severity` (1-5), `sensor_type` (`wifi`/`phone`) |
| `GET /detections/summary` | Counts of recent detections by severity and sensor type |

Example:
```bash
curl "http://127.0.0.1:8080/detections?min_severity=4&limit=20"
curl "http://127.0.0.1:8080/detections/summary"
```

## Alert Channels
Alerts (detections and tamper alarms) fan out to any number of pluggable
channels, each firing at or above its own `min_severity`. All channels are
standard-library only. Configure them under `alerting.channels` in
`config/config.yaml`:

```yaml
alerting:
  channels:
    termux:                    # on-device push (default)
      enabled: true
      min_severity: 1
    webhook:                   # POST JSON to a URL (SIEM, chat, automation)
      enabled: true
      url: "https://hooks.example.com/tigress"
      min_severity: 3
    email:                     # SMTP (STARTTLS + auth)
      enabled: true
      smtp_host: "smtp.example.com"
      smtp_port: 587
      username: "tigress@example.com"
      password: "app-password"     # or leave blank and set TIGRESS_SMTP_PASSWORD
      from: "tigress@example.com"
      to: ["soc@example.com"]
      min_severity: 4
```

The SMTP password may be supplied via the `TIGRESS_SMTP_PASSWORD` environment
variable instead of the config file. A failing channel never blocks the others. Omit the `channels` block entirely
to keep the previous Termux-only behaviour.

## Configuration
`config/config.yaml` controls sensors, detection thresholds, and alerting.
Per-sensor `buffer_limit` (default 1000) caps how many recent readings each
sensor keeps in memory. `alerting.history_size` (default 500) caps how many
recent detections are held in memory for the `/detections` API. Detection rules
live in `config/rules.yaml`.

## Runtime Protection
Running with `--secure` verifies the boot manifest and starts runtime integrity
monitoring: critical-file hashing and debugger detection, plus optional
**process monitoring**. When `security.process_monitoring` is enabled, TIGRESS
records a baseline of running processes at startup and alarms only when a
*new*, non-whitelisted process appears (each is reported once). Configure it
under `security` in `config/config.yaml`:

```yaml
security:
  process_monitoring: true
  process_whitelist: ["my-daemon"]   # extra names to treat as expected
  monitor_interval: 30               # seconds between checks
```

Alarms are written to `data/alerts/tamper.log` and dispatched through the
configured [alert channels](#alert-channels) (Termux, webhook, and/or email).

## Models
Trained models are saved to `models/`. Delete them to retrain. The engine falls
back to rule-based detection until training is complete.

## Audit Logs
Logs are written to `data/audit/audit_YYYYMMDD.log`. Each entry is ECDSA-signed
and hash-chained. Verify integrity:
```python
from src.security.audit_log import AuditLog
print(AuditLog().verify_integrity())
```

## Development & Testing
```bash
pip install -r requirements-dev.txt
pytest
```
The test suite is hermetic — it writes only to pytest temp directories and does
not require real sensors or Termux.

## License
MIT
