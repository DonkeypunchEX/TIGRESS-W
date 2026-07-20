# TIGRESS – Threat Intelligence Grid for Android

Security monitoring framework for Android/Termux: WiFi anomaly detection, physical tamper detection, and ML-based threat analysis.

## Features
- WiFi scanning with new-BSSID and SSID-rule alerting
- Bluetooth/BLE scanning with new-device, proximity, and tracker alerting
- Accelerometer-based tamper detection
- Isolation Forest anomaly detection (auto-trains on first run)
- Cross-sensor correlation engine (persistence/tracking, coordinated activity,
  burst patterns) with Pyramid of Pain indicator ranking
- Offline threat-intel enrichment (OUI vendor, tracker fingerprints,
  randomized-MAC detection)
- One-knob security posture (`relaxed`/`normal`/`aggressive`/`paranoid`)
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
| `GET /detections` | Recent detections, newest first (in-memory). Query params: `limit`, `min_severity` (1-5), `sensor_type` (`wifi`/`phone`/`bluetooth`/`correlation`/`network`), `pyramid_level` (`address`/`artifact`/`tool`/`ttp`) |
| `GET /detections/summary` | Counts of recent detections by severity, sensor type, and Pyramid of Pain band |
| `GET /events` | Query the durable event store (persists across restarts). Params: `limit`, `event_type`, `min_severity`, `sensor_type`, `since`/`until` (ISO), `q` (description substring) |
| `GET /events/summary` | Counts of persisted events by severity, type, and sensor over a `since`/`until` window |
| `GET /analytics` | Time-bucketed event counts (`bucket` = `hour`/`day`/`month`) plus top descriptions, filtered by `event_type`, `since`/`until` |
| `POST /ingest/suricata` | Ingest Suricata EVE alert(s) from a router/gateway. Body: one EVE record or a list. Always requires the bearer token (returns 403 if none is configured) |

### Persistent event store (SQLite)
`/detections` is a fast in-memory view of the most recent detections and is lost
on restart. For durable, queryable history, TIGRESS also writes every detection
(and other forensic events) to a SQLite database — the standard-library
`sqlite3`, no extra dependencies. It backs `/events`, `/events/summary`, and
`/analytics`, and complements (does not replace) the tamper-evident forensic
JSONL and signed audit log, which remain the authoritative record. Enable it via
`alerting.event_db` (default `data/events.db`; set empty to disable). All queries
are parameterized — there is no raw-SQL endpoint.

### Authentication
The data endpoints (`/`, `/sensors`, `/detections`, `/detections/summary`,
`/events`, `/events/summary`, `/analytics`) can require a bearer token. Set `server.api_token` in the config **or** the
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

The forensic log can rotate and self-prune. `alerting.forensic_max_bytes`
(default 0 = never) rotates the active log under a dated filename once it would
exceed that size, and `alerting.forensic_rotation_interval` (seconds, default 0
= never) rotates on the first write after that much time has elapsed — a
size-independent trigger so retention works even on a small log. Each rotation
writes a detached `<file>.sha256` sidecar (the hash stored *separately* from the
data). `alerting.forensic_retention_days` (default 0 = keep forever) prunes
rotated logs older than the window on each rotation; set `forensic_max_bytes`
and/or `forensic_rotation_interval` for pruning to ever run.

### Security posture
One knob retunes the whole grid coherently — set `posture` in the config or
the `TIGRESS_POSTURE` environment variable (env wins):

| Posture | Behaviour |
| ------- | --------- |
| `relaxed` | Quiet daily carry: slower scans, higher alert bars |
| `normal` | Config values used exactly as written (default) |
| `aggressive` | Faster scans, lower detection/alert thresholds |
| `paranoid` | Fastest scans, lowest thresholds, doubled correlation memory, **+1 severity on every detection** |

Posture scales the values already in your config (scan intervals, confidence
threshold, alert thresholds, channel `min_severity` floors, tamper threshold,
correlation windows), so the config stays the single source of truth.

## Correlation & the Pyramid of Pain
Single detections are atomic indicators — a BSSID, a strong RSSI, one
accelerometer spike. The correlation engine watches the detection stream over
a sliding window (`detection.correlation` in the config) and promotes
patterns into TTP-level meta-detections:

- **entity_persistence** — the same BSSID/MAC recurring across scans over
  time: the signature of a tracking device or following behaviour. With
  movement context (`detection.correlation.movement`), a finding whose
  entity recurred **while the device was in motion** — recurring across
  places, not just across time — is escalated in severity; set
  `require_movement: true` to suppress stationary recurrences entirely
  (e.g. sitting near a neighbour's devices all evening)
- **cross_sensor** — multiple sensor domains (WiFi + BLE + physical) alerting
  inside one window: coordinated activity
- **burst** — raw detection volume spiking: an actively hostile environment

Your own gear is excluded via a user-curated allowlist
(`detection.correlation.allowlist` — inline entries and/or
`data/trusted_entities.txt`, one MAC per line, optionally `bt:`/`bssid:`
prefixed), so your smartwatch at strong RSSI all day never reads as a
tracker. Curate it by hand: do **not** point it at the sensors' `known_*`
files, which record every device ever seen — a tracker would allowlist
itself after one sighting.

Every detection is tagged with its Pyramid of Pain band in
`features.pyramid_level` — `address` (a MAC, trivial for an adversary to
rotate), `artifact` (SSID/name/vendor), `tool` (tracker-class hardware), or
`ttp` (behaviour over time, the hardest thing to change). Correlation
meta-detections are TTP-level by construction: an adversary can rotate a MAC
every few minutes, but they cannot stop *being near you repeatedly* without
abandoning the surveillance itself.

## Network Sensor via Suricata Ingestion
Packet inspection belongs where packets flow — a router or gateway you
control, not a non-rooted phone. Run Suricata there and forward its EVE
alerts to TIGRESS:

```bash
# e.g. tail Suricata's eve.json on the router and POST alerts to the phone
tail -F /var/log/suricata/eve.json | while read -r line; do
  curl -s -X POST -H "Authorization: Bearer $TIGRESS_API_TOKEN" \
       -H "Content-Type: application/json" -d "$line" \
       "http://<phone>:8080/ingest/suricata"
done
```

Accepted alerts become `network` detections: forensically logged, alerted,
and correlated. A recurring destination IP (beaconing/C2) can trip
`entity_persistence`, and network + wireless + physical activity together
trips `cross_sensor` — the grid sees your whole environment, not just RF.
Trusted destinations can be allowlisted with `ip:`-prefixed entries.

## Threat-Intel Enrichment
Readings are enriched offline (no network calls) before rules run, from
`config/enrichment.yaml` — a user-extendable seed of OUI→vendor prefixes,
tracker name patterns, and tracker vendors. Rules can then match what a device
*is* rather than the literal string it advertises: `vendor`,
`mac_randomized` (locally-administered bit), `tracker_name_match`, and
`is_tracker` are all rule-addressable fields. The strongest tracker detector
is the combination: a randomized-MAC device flagged by enrichment that then
trips the persistence correlation rule.

## Runtime Protection
Running with `--secure` first enforces self-validation (see
[Self-Validation](#self-validation) — startup is refused if the detector can't
be validated), then verifies the boot manifest and starts runtime integrity
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
missing, failed, or was produced by a different version (records are read from
`app.validation_dir`, default `data/validation`). On a normal startup the
dashboard only logs a warning when no current passing validation exists. Under
`--secure` it is **enforced**: if validation is needed the self-test runs
inline, and startup is refused (non-zero exit) if it fails — so a secure
deployment never serves an unvalidated or broken detector.

## Visibility & Rule Hygiene
Detection quality is bounded by visibility, so check what is actually feeding
the engine before trusting a green run:
```bash
python scripts/visibility.py          # which sensors have live CLIs + trained models
python scripts/audit_rules.py         # flag multi-behaviour rules (signal hygiene)
```
`visibility.py` exits non-zero when an enabled sensor has no telemetry CLI
("blind"). `audit_rules.py` enforces Josh Liburdi's single-behaviour "detection
signal" model, flagging rules that combine behaviours as split candidates
(`--strict` makes it a CI gate). Rules carry optional `phase`/`weight` metadata
(Jack Crook's I-BAD framing); the correlation engine's `behavioral_progression`
rule sums weight across distinct kill-chain phases per entity to recombine
signals into a TTP-level alert. Network ingestion additionally flags Bvp47-style
"SYN knock" covert channels (payload in a TCP SYN packet) as tool/TTP-band
indicators. See [`docs/DEFENSIVE_DOCTRINE.md`](docs/DEFENSIVE_DOCTRINE.md) for
the philosophy → protocol → method extraction these capabilities implement.

## Audio spectrum analysis (Phyphox)
Offline analyzer for [Phyphox](https://phyphox.org) "Audio Spectrum" exports —
useful for triaging a suspicious hum or tone. It finds spectral peaks, fits the
best fundamental `f0` and its harmonic stack (the signature of ordinary
rotating machinery), and reports only the *non-harmonic residual* as
potentially interesting. It also warns when the harmonic spacing matches the
FFT bin width, i.e. when the "stack" may be a quantization artifact.
```bash
python scripts/phyphox_harmonics.py /path/to/Audio_Spectrum_export.zip   # or the unzipped folder
```

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
