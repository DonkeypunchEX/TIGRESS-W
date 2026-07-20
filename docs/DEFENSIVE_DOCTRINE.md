# Defensive Doctrine — Philosophy, Protocol, Method

*Extracted from the NotebookLM source artifacts and mapped onto the TIGRESS codebase.*

This document distils the guiding ideas from two reviewed sources into three
operational layers and connects each one to the module that already carries it
(or should):

1. **Philosophy** — the mindset and first principles. *Why* we defend the way we do.
2. **Protocol** — the repeatable procedures. *How* the work is run, step by step.
3. **Method** — the concrete techniques, queries, and signatures. *What* we actually do.

## Sources reviewed

| Source | Nature | What it contributes |
|--------|--------|---------------------|
| **Bluenomicon: A Compendium for the Network Defender** (Splunk SURGe; ed. Baccio & Streetman) | Essay collection — leadership, incident response, detection engineering, threat hunting, forensics | Analyst mindset, the Pyramid of Pain, loosely-coupled detection, behavioural anomaly hunting, diagnostic inquiry |
| **MARLon / Zero-Trust frontline analysis** ("The Perimeter is a Lie"; *Bvp47* Equation Group teardown) | Strategic essay + top-tier backdoor case study | Presume-breach posture, covert-channel awareness, adversary evasion techniques, containment over prevention |

The three layers below are the answer to *"can we extract philosophy, protocol,
and method from these documents?"* — yes, and here they are, tied to code.

---

## Layer 1 — Philosophy

First principles that should govern every detection and response decision.

### P1. Rank indicators by adversary pain, not by how easy they are to collect
The **Pyramid of Pain** (David J. Bianco) holds that hashes and IPs are trivial
for an adversary to rotate, while **TTPs** — the behaviours themselves — are the
costliest to change. Defence effort should climb the pyramid.

> *In code:* `src/core/correlation_engine.py` already encodes the four bands
> (`PYRAMID_ADDRESS`, `PYRAMID_ARTIFACT`, `PYRAMID_TOOL`, `PYRAMID_TTP`) and
> emits meta-detections that are **TTP-level by construction** — persistence,
> coordinated activity, and burst patterns over time, not single readings.

### P2. Presume breach; defend data, not the wall
"The perimeter is a lie." 61% of organisations were breached despite record
spend. Zero Trust assumes the adversary is **already inside** and shifts the
goal from *keeping people out* to *containment and constant verification*
("never trust, always verify"). *Bvp47* is the proof: a decade-long, kernel-level
implant that lived undetected behind hardened perimeters.

> *In code:* the on-device threat model in `src/security/` (runtime integrity
> monitoring in `anti_tamper.py`, boot measurement in `secure_boot.py`,
> tamper-evident `audit_log.py`) is a presume-breach posture — it assumes the
> host itself may be compromised and continuously re-verifies.

### P3. A question well stated is a problem half solved
Dr. Chris Sanders' **Diagnostic Inquiry** frames investigation as a cognitive
loop, not a checklist. The good hunter (Ashlee Benge) is a lifelong learner who
asks *why* — putting themselves in the adversary's shoes — and is not afraid to
chase false leads.

### P4. Behaviour beats identity
Enrichment names (vendor, tracker fingerprint) are the *weakest* signals because
modern trackers rotate MACs and advertise nothing. The strong signal is
**behaviour over time**: a rotating-MAC device that keeps reappearing while you
move is tracker behaviour *whatever it calls itself*.

> *In code:* documented verbatim in `src/core/enrichment.py` and realised by the
> `movement.py` + correlation entity-persistence pairing.

### P5. Optimism and people are force multipliers (leadership)
From *Counsel of the Sages*: the most flexible team wins; the leader's key
contribution is optimism ("finding bad stuff results in good stuff"); put people
before tools; you cannot *buy* your way to security — culture eats strategy for
breakfast.

---

## Layer 2 — Protocol

Repeatable procedures distilled from the sources.

### PR1. The Diagnostic Inquiry loop (Sanders)
Run every investigation as this loop until the event is benign, fully
understood, or evidence/questions are exhausted:

1. **Observe** — an initial cue (an alert, a detection).
2. **Interpret meaning** — identify entities, relationships, and cues that compel action.
3. **Form an investigative question** — forecast what *else* must have happened; state a specific, answerable question.
4. **Seek the answer in evidence** — query the store, captures, images.
5. **Reach a conclusion** — then repeat.

> *In code:* the detection → correlation → forensic-log pipeline
> (`detection_engine.py` → `correlation_engine.py` → `forensic_logger.py` /
> `event_store.py`) is the evidence substrate this loop runs on.

### PR2. Climb the Pyramid under pressure (Bianco's engagement)
When an adversary defeats a detection tier, **move up**, don't rebuild the same
tier:

Hashes/IPs → Network/Host artifacts → **Tool heartbeat** (transport-independent
C2 signature) → **TTP** (e.g. fixed-size encrypted WinRAR staging archives).
Making each tier costly is what forces an adversary to give up.

### PR3. Presume-breach rollout: Build → Detect → Prevent
Zero Trust is a multi-year evolution, not a purchase. Build the architecture,
run it in **Detection mode** first, and only then move to **Prevention**. Culture
adoption is Goal #1 — identity and least-privilege make HR a frontline player.

> *In code:* mirrors TIGRESS's `--train` (baseline) → normal (detect) → `--secure`
> (enforce) progression and the `posture` knob (`relaxed`→`paranoid`).

### PR4. Incident notification under ambiguity (Nather)
When you cannot prove an event is benign, **assume the worst** (assume accessed
data was read). Notification is multi-staged, driven by legal/contractual
timeliness, and delivered with transparency and empathy even when incomplete.

### PR5. The three P's of finishing (Wharton)
**Practice** (constant learning, listen as much as talk) → **Pivot** (stay
coachable, embrace change) → **Persistence** ("finish the drill"; a control isn't
done when the tool is bought — push past roadblocks to real implementation).

---

## Layer 3 — Method

Concrete, implementable techniques.

### M1. Loosely-coupled detection signals (Liburdi)
Don't write one alert per malware family. Emit low-level **detection signals**
(one behaviour each), store them keyed by a **consistent event identifier**
(UUID/hash), and **correlate signals into alerts** later. The same signal store
feeds hunting, intel, and IR. Migration rule: split multi-behaviour alerts into
signals; convert single-behaviour alerts directly to signals; recombine.

> *In code:* `Detection` objects already carry a unique `id`; `event_store.py`
> and `detection_store.py` are the signal store; `correlation_engine.py` is the
> recombination layer. This is Liburdi's architecture in miniature.

### M2. Behavioural anomaly scoring with Isolation Forest (Crook, I-BAD)
Crook's full I-BAD method tags detections with a **phase** and a **weight**,
aggregates per-entity scores (total weight, distinct phases, distinct detection
counts), then feeds the raw numeric output into an **Isolation Forest** to
surface outliers — cutting thousands of results to a reviewable few.

> *In code (implemented):* `Detection` carries `phase`/`weight`
> (`detection_engine.py`), and the correlation engine's `behavioral_progression`
> rule scores each entity by **cumulative per-phase weight** and **distinct
> phase count**, emitting a TTP-level meta-detection when both cross their
> thresholds (`correlation_engine.py`).
>
> *Future work:* the deterministic threshold above is the on-device-friendly
> form. The remaining I-BAD step — feeding per-entity score *vectors* into the
> `IsolationForest` already trained in `detection_engine.py` to rank outliers,
> plus distinct-detection-count as a third axis — is not yet wired up.

### M3. Covert-channel & evasion awareness (Bvp47)
Top-tier implants hide in places defenders don't look:
- **SYN Knock** — payload smuggled in the initial TCP SYN packet (most sensors ignore SYN payloads).
- **BPF covert channel** — packets captured before the normal protocol stack.
- **Anti-sandbox / anti-analysis** — environment checksums, `/boot` file counts, API flooding, `setrlimit` core-dump suppression, self-destruct on host mismatch.

> *Method for TIGRESS:* treat unexpected inbound SYN payloads and anomalous
> low-level packet behaviour as **tool/TTP-band** indicators in `network_ingest.py`;
> and harden our own forensics against the mirror-image of these evasions
> (integrity of `audit_log`, non-suppressible evidence capture).

### M4. LOLBin hunting on macOS/Linux (Howard, GTFOBins)
Hunt abusable native binaries, not just Windows:
- `wget`/`curl` → suspicious extensions (`.zip`,`.rar`), temp paths, Tor exit nodes.
- `crontab` → creation/edit (`-e`) or listing (`-l`) for persistence.
- `openssl` → Base64 encode/decode (post-exploitation staging).
- `find` → `-exec` (recon + arbitrary execution).

### M5. Forensics-first acquisition order (Lee)
Capture the **most volatile first**: memory before disk. Memory via FTK
Imager / BriMor Live Response, analyse with **Volatility** (`pslist`, `netscan`,
`cmdscan`, `hashdump`). Network via **Wireshark**/`tcpdump` — start at the
Protocol Hierarchy, then Endpoints/Conversations, then filter down.

> *In code:* aligns with `evidence.py` and the version-stamped evidence manifests
> (`version.py`) — every artifact must be attributable to the exact software that
> produced it.

### M6. Data-driven detection prerequisites (Hartong)
Detection quality is bounded by **visibility**. Establish logging baselines
(JSCU-NL, UKNCSC), audit what is actually enabled (`auditpol /get /category:*`),
verify enterprise-wide via GPO analysis, and generate/inspect telemetry per
technique before trusting a detection.

---

## Codebase mapping at a glance

| Doctrine element | Layer | TIGRESS module |
|------------------|-------|----------------|
| Pyramid of Pain bands | Philosophy P1 / Protocol PR2 | `core/correlation_engine.py` |
| Presume breach / runtime integrity | Philosophy P2 | `security/anti_tamper.py`, `security/secure_boot.py`, `security/audit_log.py` |
| Behaviour beats identity | Philosophy P4 | `core/enrichment.py`, `core/movement.py` |
| Build → Detect → Prevent | Protocol PR3 | `--train` / normal / `--secure`, `core/posture.py` |
| Loosely-coupled signals | Method M1 | `core/event_store.py`, `core/detection_store.py`, `core/correlation_engine.py` |
| Isolation-Forest anomaly scoring | Method M2 | `core/detection_engine.py` |
| Covert-channel awareness | Method M3 | `core/network_ingest.py` |
| Forensics & evidence integrity | Method M5 | `core/evidence.py`, `utils/forensic_logger.py`, `version.py` |

## From doctrine to code (implemented)

The four gaps this review identified between the source doctrine and the code
have now been closed:

- **I-BAD phase/weight metadata (M2).** `Detection` carries optional `phase` and
  `weight` fields (`core/detection_engine.py`); the correlation engine's
  `behavioral_progression` rule sums weight across distinct phases per entity and
  emits a TTP-level meta-detection when an entity progresses through the kill
  chain (`core/correlation_engine.py`).
- **SYN-payload covert-channel indicators (M3).** `network_ingest.py` detects the
  Bvp47 "SYN knock" (a TCP SYN packet carrying a payload) and raises it to the
  tool/TTP band — even when no IDS signature matched, since covert-channel
  implants are built to evade signatures.
- **Signal-migration discipline (M1).** `core/rule_audit.py` +
  `scripts/audit_rules.py` flag multi-behaviour rules as candidates for splitting
  into single-behaviour signals. `config/rules.yaml` keeps one intentional
  multi-behaviour rule, documented inline, with the audit surfacing it rather
  than silently changing detection coverage.
- **Visibility baseline check (M6).** `selftest.visibility_report()` +
  `scripts/visibility.py` report which enabled sensors have live telemetry CLIs
  and trained models before a green run is trusted (`ok: false` when a sensor is
  blind).

Rules now also carry `phase`/`weight` metadata so signals feed progression
scoring, and the `behavioral_progression` correlation rule is the mechanism that
recombines those single-behaviour signals into higher-order alerts (Liburdi).
