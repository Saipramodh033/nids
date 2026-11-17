# 02 — Architecture

This is the engineering reference: components, data flow, every file's job, the detection
logic with exact thresholds, the correlator's fusion rules, the ML model, and the
deployment topology.

---

## 1. Component diagram

```
                        ┌───────────────────────────────────────────────────────────┐
                        │                     NIDSPipeline (pipeline.py)             │
                        │                                                            │
  ┌───────────────┐     │   ┌──────────────┐     ┌──────────────┐                    │
  │ packet_capture│     │   │ FlowManager  │     │   Flow       │   18-feature vector │
  │   (Scapy)     │────────►│(flow_manager)│────►│  (flow.py)   │────────┐           │
  │ parse packet  │ packet  │ 5-tuple keys │     │ per-flow     │        │           │
  └───────────────┘  dicts  │ expiry heap  │     │ statistics   │        │           │
                        │   └──────────────┘     └──────────────┘        │           │
                        │                                                ▼           │
                        │                        ┌───────────────┐  ┌──────────────┐ │
                        │                        │ RuleEngine    │  │ NIDSModel    │ │
                        │                        │ (rule_engine) │  │ (model.py)   │ │
                        │                        │ threshold +   │  │ Scaler + RF  │ │
                        │                        │ cross-flow    │  │ (ML)         │ │
                        │                        └──────┬────────┘  └──────┬───────┘ │
                        │                               │  rule result     │ ml pred │
                        │                               ▼                  ▼         │
                        │                        ┌──────────────────────────────┐    │
                        │                        │ CorrelationEngine            │    │
                        │                        │ (correlator.py) fuse → verdict│    │
                        │                        └──────────────┬───────────────┘    │
                        │                                       ▼                    │
                        │                        ┌──────────────────────────────┐    │
                        │                        │ RiskScorer (risk_scorer.py)  │    │
                        │                        │  verdict → risk + severity   │    │
                        │                        └──────────────┬───────────────┘    │
                        │                                       ▼                    │
                        │                        ┌──────────────────────────────┐    │
                        │                        │ AlertManager (alerts.py)     │    │
                        │                        │ dedup · rate-limit · store   │    │
                        │                        └──────────────┬───────────────┘    │
                        └───────────────────────────────────────┼────────────────────┘
                                                                 ▼
                                             ┌──────────────────────────────┐
                                             │ Streamlit dashboard          │
                                             │ (dashboard.py + dashboard_data)│
                                             │ KPIs · charts · alert table  │
                                             └──────────────────────────────┘
```

## 2. Data-flow (one flow's life)

```
packet(s) ─► FlowManager.process_packet ─► (flow completes/expires)
          ─► Flow.get_features() ─► [18 floats]
          ─► RuleEngine.process_flow(flow)      → RuleResult(prediction, confidence, triggered_rules)
          ─► CorrelationEngine.correlate(features, rule_result)
                                               → DetectionResult(final_prediction, combined_confidence,
                                                 rule_*, ml_*, ml_top3, explanation)
          ─► RiskScorer.score(detection)        → RiskResult(risk_score 0–100, severity)
          ─► AlertManager.create_alert(...)     → Alert (or deduped/suppressed)
```

---

## 3. File-by-file map

| File | Responsibility |
|------|----------------|
| `config.py` | **Single source of truth for all thresholds** — `FlowConfig`, `RuleConfig`, `SEVERITY_MAP`. Every tunable number lives here with a rationale comment. |
| `packet_capture.py` | Scapy `sniff()` wrapper; `parse_packet_info()` extracts the 5-tuple, flags, size, timestamp. **IPv4/TCP-UDP only.** |
| `flow.py` | The `Flow` object: per-direction packet/byte counts, TCP flag counters, duration, size stats, and `get_features()` → the 18-feature vector. |
| `flow_manager.py` | Groups packets into flows by canonical 5-tuple; a heap-based expiry schedule returns completed flows. |
| `features.py` | The canonical **18-feature schema** + TCP flag bit-masks — shared by extraction, training, and inference so they never drift. |
| `rule_engine.py` | The rule-based detector: DoS, port scan, brute force, reconnaissance. Per-flow + cross-flow (time-windowed) state. Returns a `RuleResult`. |
| `model.py` | `NIDSModel`: loads/holds the `StandardScaler` + `RandomForestClassifier`, exposes `predict()` and probabilities. |
| `correlator.py` | `CorrelationEngine.correlate()` — fuses rule + ML into one `DetectionResult` (cases A–E, see §5). |
| `risk_scorer.py` | Maps prediction + confidence to a 0–100 risk score within per-class ranges and a severity label. |
| `alerts.py` | `AlertManager`: builds `Alert` records, de-duplicates (5-tuple + attack type in a 30 s window), per-source rate-limits, filters by severity, thread-safe in-memory store. |
| `pipeline.py` | `NIDSPipeline` wires the whole chain with per-stage error isolation; `ProcessingWorker` drains a packet queue on a background thread; stats + graceful shutdown. |
| `dashboard.py` | Streamlit UI "Sentinel": capture controls, live KPIs/charts, recent-alerts table + per-alert detail. Runs capture in a worker thread. |
| `dashboard_data.py` | Pure aggregation helpers for the dashboard (KPIs, counts) — no UI. |
| `train_model.py` | Trains the RandomForest on a CICIDS2017 sample and saves `models/nids_model.joblib`. |
| `retrain_model.py` | Retrains on CICIDS2017 **+ live-captured** flows (the path to making the ML actually useful on live traffic). |
| `data_extractor.py` | CICIDS2017 CSV → 18-feature rows + label mapping to the 5 classes. |

---

## 4. Detection rules (rule_engine.py) — exact logic

All thresholds come from `config.py` (`RuleConfig`). The engine evaluates **all** rules
and keeps the **highest-confidence** match (`max(confidence)`); if none fire, the flow is
BENIGN.

### DoS — `_check_dos` + `_check_dos_cross_flow`
- Per-flow: packet rate ≥ `DOS_PACKETS_PER_SECOND` (**100 pps**), or byte rate ≥
  `DOS_BYTES_PER_SECOND` (**100 000 Bps**), or SYN ratio ≥ `DOS_SYN_RATIO` (**0.5**) with
  ≥ `DOS_MIN_SYN_COUNT` (**3**) SYNs.
- Cross-flow: SYN rate across flows from one source over a **1 s** window.
- Guards: minimum packet counts to avoid flagging tiny flows / normal short connects.

### Port scan — `_check_port_scan`
- **Cross-flow (`cross_flow_port_scan`):** one source IP touched ≥
  `PORT_SCAN_MIN_UNIQUE_PORTS` (**10**) unique destination ports within
  `PORT_SCAN_TIME_WINDOW` (**10 s**). Confidence `0.5 + 0.05 × (ports − 10)`, capped 0.85.
- **Per-flow (`syn_only_probe`):** a flow with SYN but no ACK and ≤
  `PORT_SCAN_MAX_PACKETS` (**5**) packets. Confidence 0.4.
- State used: `_port_activity[src_ip][dst_port]`. Loopback sources are skipped (local OS
  noise causes false positives).

### Brute force — `_check_brute_force`
- Destination port must be in `BRUTE_FORCE_PORTS` (**22, 23, 2323, 80, 443, 139, 445**).
- ≥ `BRUTE_FORCE_MIN_ATTEMPTS` (**5**) attempts within `BRUTE_FORCE_TIME_WINDOW` (**30 s**).
- A "login attempt" flow is short: ≤ `BRUTE_FORCE_MAX_PACKETS_PER_FLOW` (**3**) packets,
  ≤ `BRUTE_FORCE_MAX_DURATION` (**1 s**), no PSH (data) if `BRUTE_FORCE_NO_PSH_REQUIRED`.
- A **refused SYN probe** (RST, syn<2) is **not** counted (that's a scan, not a login).
- ⚠️ In practice this rule does not fire — see file 04 (`04_STATUS_AND_LIMITATIONS.md`).

### Reconnaissance — `_check_reconnaissance`
- **`multi_host_scan`:** one source contacted ≥ `RECON_MIN_UNIQUE_IPS` (**3**) unique
  destination IPs within `RECON_TIME_WINDOW` (**30 s**).
- **`multi_port_scan`:** one source touched ≥ `RECON_MIN_UNIQUE_PORTS` (**5**) unique
  ports across all targets (reuses `_port_activity` — hence the overlap with PORT_SCAN).
- State used: `_host_activity[src_ip][dst_ip]` + `_port_activity[src_ip]`.

> **Shared-state overlap:** PORT_SCAN's `cross_flow_port_scan` (≥10 ports) and
> RECON's `multi_port_scan` (≥5 ports) read the **same** per-source port counter. A dense
> single-host scan crosses both, and the engine keeps whichever has higher confidence —
> which is why one `nmap` run produces a mix of PORT_SCAN and RECONNAISSANCE alerts.

---

## 5. Correlator (correlator.py) — fusion cases

`correlate(features, rule_result)` runs the ML model and returns one `DetectionResult`
via five cases. **The rule engine is authoritative; the ML model is advisory.**

| Case | Condition | Final verdict | Confidence |
|------|-----------|---------------|------------|
| **A** | Rule + ML agree (same non-benign class) | that class | probability union `1−(1−r)(1−m)` (boosted) |
| **B** | Rule + ML both attack, different classes | **higher-confidence** source's class | winner × 0.85 |
| **C** | Rule = BENIGN, ML = attack | **BENIGN** ← *ML advisory: cannot alert alone* | 0.0 (ML opinion still recorded/shown) |
| **D** | ML = BENIGN, Rule = attack | the **rule's** class | rule × 0.80 |
| **E** | Both BENIGN | BENIGN | low |

> **Case C is the key design decision.** Originally it trusted the ML alone (final =
> ML's class), which produced false positives on live traffic. It now returns BENIGN so
> the ML cannot raise an alert by itself, while `ml_prediction` / `ml_confidence` /
> `ml_top3` are still populated for the analyst. See file 04 for the full rationale.

---

## 6. The ML model (model.py)

- **Pipeline:** `StandardScaler` → `RandomForestClassifier`, saved as
  `models/nids_model.joblib` via joblib.
- **Features:** the same 18 flow features (schema in `features.py`).
- **Classes (integer-ordered):** `0=BENIGN, 1=PORT_SCAN, 2=BRUTE_FORCE, 3=DOS, 4=RECONNAISSANCE`.
- **Training:** `train_model.py` on a CICIDS2017 sample (`data_extractor.py` maps CICIDS
  labels → the 5 classes). `retrain_model.py` can merge CICIDS2017 + live-captured flows.
- **Known weakness — domain shift:** the shipped model was trained on CICIDS2017 **CSV
  flow statistics** (CICFlowMeter features), but at runtime it is fed the features that
  `flow.py` computes from live packets. The distributions differ, so on live traffic the
  model mostly predicts BENIGN or noise. This is *why* it is advisory, and *why*
  retraining on live lab flows (`retrain_model.py`) is the real fix.
- **Deployment note:** the `.joblib` was pickled with scikit-learn 1.5.2 but the Ubuntu
  venv runs 1.9.1 → an `InconsistentVersionWarning` on load. Pin the version or retrain
  in-environment for a clean deployment.

---

## 7. Deployment topology (the lab)

```
┌────────────────────────┐         host-only network 192.168.56.0/24 (VirtualBox)
│ Windows host (192.168.56.1)                                                      │
│  • Chrome → http://192.168.56.107:8501  (views the dashboard)                    │
└───────────────┬────────────────────────────────────────────────────────────────┘
                │
   ┌────────────┴─────────────┐                        ┌───────────────────────────┐
   │ Ubuntu sensor .107        │  ◄──── attacks ────────│ Kali attacker .105/.103   │
   │  • runs Sentinel          │   nmap / hping3 / hydra │  • nmap -sS (port scan)   │
   │  • capture iface enp0s8   │                        │  • hping3 (DoS)           │
   │  • Streamlit :8501        │                        │  • hydra (brute force)    │
   │  • .venv (Python 3.14)    │                        └───────────────────────────┘
   └───────────────────────────┘
```

- **Sensor:** Ubuntu `192.168.56.107`, capture interface **`enp0s8`** (the host-only NIC;
  `enp0s3` is NAT and is *not* the capture interface). Capture needs root (CAP_NET_RAW).
- **Attacker:** Kali `192.168.56.105`; note it also has `192.168.56.103` on the same
  subnet and typically **routes attacks from `.103`** — alerts will show source `.103`.
- **Isolation:** everything is on the VirtualBox host-only `192.168.56.0/24` net — a
  self-contained lab, no external exposure.

---

## 8. Threading / runtime model

- `ProcessingWorker` (in `pipeline.py`) drains a packet queue on a **daemon thread**, so
  packet capture (producer) and the detection pipeline (consumer) run independently.
- The dashboard starts capture in its own worker thread per Streamlit session
  (`_capture_worker` → `pipeline.start_capture(interface=...)`).
- The alert store and worker state are guarded for thread safety.
- Flows expire via a heap keyed on expiry time; expiry is checked as packets arrive.
