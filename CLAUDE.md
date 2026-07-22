# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

TIGRESS is a counter-surveillance / security-monitoring framework for Android
phones running Termux: WiFi/BLE/accelerometer sensing, rule + ML detection,
cross-sensor correlation, and a FastAPI dashboard. It also accepts Suricata
EVE alerts from a router as a "network" sensor. Everything must work without
real sensors (dummy mode) — the test suite and the end-to-end demo never touch
Termux.

## Commands

Dependencies are installed automatically by the `.claude/hooks/session-start.sh`
SessionStart hook in remote sessions (it also exports `PYTHONPATH="."` so
`from src...` imports resolve). Manually: `pip install -r requirements-dev.txt`.

```bash
pytest                                   # full suite (hermetic, no sensors needed)
pytest tests/test_correlation.py         # one file
pytest tests/test_correlation.py::test_name   # one test
ruff check src tests                     # lint (CI-enforced)
bandit -r src -ll                        # security scan (CI-enforced)
pip-audit -r requirements.txt            # dependency audit (CI-enforced)

python scripts/demo_end_to_end.py        # full pipeline demo, no Android needed
python scripts/selftest.py --record-dir data/validation   # golden-dataset validation gate
python scripts/visibility.py             # which sensors have live CLIs + trained models
python scripts/audit_rules.py            # flag multi-behaviour rules (signal hygiene)
bash scripts/tigress_launcher.sh [--train|--secure|--dummy]  # run on-device
```

CI (`.github/workflows/ci.yml`) runs ruff + pytest on Python 3.10–3.12 plus the
bandit/pip-audit security-scan job, on every push and PR.

## Architecture

Data flows one way through a pipeline; understanding it requires connecting
several modules:

1. **Sensors** (`src/sensors/`) — subclasses of `BaseSensor`, which owns a
   bounded reading buffer and a subscriber list. Real sensors shell out to
   OS scanning tools; `DummySensor` fabricates readings. The backend is chosen
   per host OS (`src/core/platform.py`): Termux/POSIX sensors in
   `SENSOR_REGISTRY`, Windows sensors (`src/sensors/windows/`: `netsh wlan` +
   PowerShell `Get-PnpDevice`) in `WINDOWS_SENSOR_REGISTRY`, selected by
   `active_sensor_registry()` in `src/core/sensor_manager.py`. Windows has no
   accelerometer analogue, so the `phone` sensor is skipped there. All sensors
   emit the same reading schema regardless of platform.
2. **SensorManager** (`src/core/sensor_manager.py`) — starts/stops configured
   sensors and routes every reading into the `DetectionEngine`.
3. **DetectionEngine** (`src/core/detection_engine.py`) — the hub. Per reading:
   enrich (offline threat intel: OUI vendor, tracker fingerprints,
   randomized-MAC — `src/core/enrichment.py` + `config/enrichment.yaml`), run
   YAML rules (`config/rules.yaml`), run a per-sensor-type Isolation Forest
   (models persisted in `models/`, rule-only fallback until trained). Emits
   `Detection` dataclasses, which carry optional `phase`/`weight` metadata
   (Jack Crook's I-BAD framing) that the correlation engine scores.
4. **CorrelationEngine** (`src/core/correlation_engine.py`) — sliding-window
   pattern detection over the detection stream, emitting TTP-level
   meta-detections (`entity_persistence`, `cross_sensor`, `burst`, and
   `behavioral_progression` — an entity accumulating `weight` across distinct
   kill-chain `phase`s, recombining single-behaviour signals into one alert).
   Deliberately decoupled: detections cross this boundary as **plain dicts**
   (`Detection.__dict__`) so it has no import dependency on the engine. Every
   detection is tagged with a Pyramid of Pain band
   (`address`/`artifact`/`tool`/`ttp`) via `classify_pyramid_level`.
   `MovementTracker` (`src/core/movement.py`) escalates persistence findings
   that recur while the device is moving. A user-curated allowlist suppresses
   the owner's own devices — never auto-populate it from the sensors'
   `known_*` files.
5. **Outputs** — every detection fans out to the `ForensicLogger` (JSONL,
   rotation + detached SHA-256 sidecars), the `AlertDispatcher`
   (`src/utils/alerting.py`: pluggable termux/windows/webhook/email channels,
   each with its own `min_severity`, async worker-thread delivery by default,
   webhook egress allowlist; the on-device channel — `termux` push or `windows`
   toast — is picked by `default_local_channel()` and each no-ops off its own
   platform), the in-memory `DetectionStore` that backs the dashboard's
   `/detections` API, and a durable SQLite `EventStore`
   (`src/core/event_store.py`, stdlib `sqlite3`, parameterized queries only)
   that backs `/events`, `/events/summary`, and `/analytics` across restarts.
6. **Dashboard** (`src/dashboard/app.py`) — FastAPI app that owns the
   `SensorManager` lifecycle. Read-only JSON endpoints plus
   `POST /ingest/suricata` (→ `src/core/network_ingest.py`), which turns router
   Suricata EVE alerts into `network` detections that join the same
   forensic/alert/correlation flow — and independently flags Bvp47-style "SYN
   knock" covert channels (payload in a TCP SYN packet) as tool/TTP-band
   detections even when no IDS signature matched. Bearer-token auth (`server.api_token` or
   `TIGRESS_API_TOKEN`; constant-time comparison); `/health` is always open;
   the Suricata ingest endpoint *requires* a token and 403s if none is
   configured.

**Cross-cutting:**

- **Posture** (`src/core/posture.py`): one knob
  (`posture` config key or `TIGRESS_POSTURE` env, env wins:
  `relaxed`/`normal`/`aggressive`/`paranoid`) that *scales* the values already
  in `config/config.yaml` (scan intervals, thresholds, correlation windows,
  channel severity floors) rather than replacing them — the config stays the
  single source of truth. New tunables should respect this pattern.
- **Security modules** (`src/security/`): `audit_log` (hash-chained,
  ECDSA-signed daily logs with `verify_integrity`/`verify_detailed`),
  `secure_config` (encrypted config), `secure_boot` + `anti_tamper` (boot
  manifest verification, file/process integrity monitoring behind `--secure`),
  `secure_communication` (mTLS for the dashboard).
- **Forensic-evidence discipline**: hashes are stored *separately* from the
  data they protect (manifest sidecars, `scripts/export_evidence.py` bundles
  verified by `scripts/verify_bundle.py`), following NIST IR 8387 / NIJ
  practice. Preserve this property when touching evidence/logging code.

## Conventions

- Python 3.8+ syntax (`target-version = "py38"` in `ruff.toml`), line length
  100, import sorting via ruff `I` rules.
- Docstrings are **required on everything public in `src/`** (ruff `D100`–`D104`)
  and deliberately **not** required in `tests/` — tests are self-documenting by
  name and may reach into private attributes. CodeRabbit's own docstring check
  is intentionally disabled in `.coderabbit.yaml` for this reason; don't
  re-enable it.
- Tests must stay hermetic: write only to pytest temp directories, never
  require Termux, real sensors, or the network.
- Alert channels are standard-library only (no new runtime deps for delivery
  mechanisms), and a failing channel must never block the others.
