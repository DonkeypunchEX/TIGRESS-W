# TIGRESS – Threat Intelligence Grid for Android

Security monitoring framework for Android/Termux: WiFi anomaly detection, physical tamper detection, and ML-based threat analysis.

## Features
- WiFi scanning with new-BSSID and SSID-rule alerting
- Bluetooth/BLE scanning with new-device, proximity, and tracker alerting
- Accelerometer-based tamper detection
- Isolation Forest anomaly detection (auto-trains on first run)
- Encrypted configuration (hardware-backed when available)
- Tamper-proof audit logging (hash chain + ECDSA signatures)
- Runtime file and process integrity monitoring
- Mutual TLS for dashboard communication
- Termux push notifications

## Limitations (Android 13+)
- `termux-wifi-scaninfo` returns cached data — scans may be stale
- Bluetooth scanning requires `termux-bluetooth-scaninfo`; the sensor disables
  itself if it is unavailable
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

## Try it end-to-end (no Android)
See the detection pipeline work in one command — it stands up a local webhook
receiver, feeds the real engine threat-shaped WiFi/BLE scans, and shows
detections firing, alerts delivered over HTTP, and the authenticated
`/detections` API returning them:
```bash
python scripts/demo_end_to_end.py
```

## Dashboard API
The dashboard exposes read-only JSON endpoints:

| Endpoint | Description |
| -------- | ----------- |
| `GET /` | Status and sensor list |
| `GET /sensors` | Per-sensor status |
| `GET /health` | Liveness probe |
| `GET /detections` | Recent detections, newest first. Query params: `limit`, `min_severity` (1-5), `sensor_type` (`wifi`/`phone`/`bluetooth`) |
| `GET /detections/summary` | Counts of recent detections by severity and sensor type |

### Authentication
The data endpoints (`/`, `/sensors`, `/detections`, `/detections/summary`) can
require a bearer token. Set `server.api_token` in the config **or** the
`TIGRESS_API_TOKEN` environment variable; when set, requests without a valid
`Authorization: Bearer <token>` header get `401`. `/health` is always open for
liveness probes. If neither a token nor `--secure` (mTLS) is configured, the
dashboard logs a warning that it is serving data unauthenticated.

Example:
```bash
export TIGRESS_API_TOKEN=s3cr3t
curl -H "Authorization: Bearer $TIGRESS_API_TOKEN" \
  "http://127.0.0.1:8080/detections?min_severity=4&limit=20"
curl -H "Authorization: Bearer $TIGRESS_API_TOKEN" \
  "http://127.0.0.1:8080/detections/summary"
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
      allowed_hosts: ["hooks.example.com"]   # egress allowlist (see below)
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

### Asynchronous delivery
By default (`alerting.async_dispatch: true`) alerts are delivered on background
worker threads, so a slow or hung webhook/SMTP server never stalls the detection
pipeline. Tune `async_workers` (thread count) and `queue_size` (max queued
alerts before new ones are dropped with a warning). Set `async_dispatch: false`
to deliver inline in the detection thread instead.

### Webhook egress allowlist
The webhook channel accepts an `allowed_hosts` list. When set, TIGRESS only
POSTs to those hosts and refuses any other target — an egress control that
bounds where alerts (and anyone who can influence the configured URL) can send
traffic. Redirects are never followed, so an allow-listed host cannot bounce the
request elsewhere. Leave it empty/unset for unrestricted delivery.

## Configuration
`config/config.yaml` controls sensors, detection thresholds, and alerting.
Per-sensor `buffer_limit` (default 1000) caps how many recent readings each
sensor keeps in memory. `alerting.history_size` (default 500) caps how many
recent detections are held in memory for the `/detections` API. Detection rules
live in `config/rules.yaml`.

The forensic log can rotate and self-prune: `alerting.forensic_max_bytes`
(default 0 = never) rotates the active log under a dated filename once it would
exceed that size, writing a detached `<file>.sha256` sidecar (the hash stored
*separately* from the data), and `alerting.forensic_retention_days` (default 0 =
keep forever) prunes rotated logs older than the window.

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
audit = AuditLog()
print(audit.verify_integrity())        # True/False

# Localize corruption instead of a bare pass/fail: verify_detailed() checks
# each record independently and reports exactly which are suspect, so one
# tampered entry does not invalidate everything after it.
report = audit.verify_detailed()
print(report["ok"], report["entries_checked"], report["errors"])
```

## Evidence Export
Package forensic records into a self-contained, tamper-evident bundle for
handoff or retention, following NIST IR 8387 / NIJ digital-evidence-preservation
practice — a NIST-approved SHA-256 recorded in a manifest **stored separately**
from the data, an optional ECDSA signature, and a documented chain of custody
(producing tool + version, host, capture window):
```bash
python scripts/export_evidence.py --out ./bundle \
  --forensic-log data/alerts/forensic.jsonl \
  --since 2026-01-01T00:00:00+00:00 --types detection --case-id CASE-123 --sign
```
The bundle contains `evidence.jsonl`, `manifest.json` (provenance + the
separately-stored hash), `manifest.sig` (when `--sign` is used), and
`CHAIN_OF_CUSTODY.txt`. Verify a bundle independently — recomputes the evidence
hash against the manifest, checks the record count, and validates the signature
when present:
```bash
python scripts/verify_bundle.py ./bundle
```
It exits non-zero if any check fails, so it can gate an evidence handoff. A valid
signature alone only proves the bundle is internally consistent with whatever key
it ships — pass `--public-key <base64>` (the trusted signer's
`AuditLog.public_key_b64`) to also require it was signed by that specific key,
which is what establishes authenticity.

## Self-Validation
Validate the detector against a frozen golden dataset and record the result —
the NIJ practice of validating a forensic tool against a known dataset,
retaining the report, and revalidating after every update:
```bash
python scripts/selftest.py --record-dir data/validation
```
It runs the real engine over the golden dataset, confirms the expected
detections fire, writes a versioned `validation_<version>_<timestamp>.json`
record, and exits non-zero on any failure (usable as a CI/release gate).
`src.core.selftest.needs_revalidation(dir)` reports when the latest record is
missing, failed, or was produced by a different version. On startup the
dashboard logs a warning when no current passing validation exists (records are
read from `app.validation_dir`, default `data/validation`), nudging you to run
the self-test before relying on detections.

## Development & Testing
```bash
pip install -r requirements-dev.txt
pytest
ruff check src tests
```
The test suite is hermetic — it writes only to pytest temp directories and does
not require real sensors or Termux. `ruff` lints the code and enforces docstrings
on the `src/` package (see `ruff.toml`); CI runs both on Python 3.10–3.12.

### Security scanning
CI also runs a `security-scan` job on every push and pull request:
[`bandit`](https://bandit.readthedocs.io/) statically scans `src/` for common
security issues (medium severity and above), and
[`pip-audit`](https://pypi.org/project/pip-audit/) audits the pinned
dependencies for known vulnerabilities. Run them locally with:
```bash
bandit -r src -ll
pip-audit -r requirements.txt
```

## License
MIT
