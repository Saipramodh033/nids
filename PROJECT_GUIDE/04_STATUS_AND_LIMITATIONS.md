# 04 — Status, Limitations & Design Decisions

The honest state of the project, backed by **live measurements** from a Kali→Ubuntu lab
run. Read this to know exactly what works, what doesn't, and why.

---

## 1. Detection status (measured live)

| Attack class | Status | Evidence (live Kali `.103` → Ubuntu `.107`) |
|--------------|--------|---------------------------------------------|
| **Port scan** | ✅ Works | `nmap -sS` → 225 PORT_SCAN alerts (`cross_flow_port_scan`, `syn_only_probe`) |
| **Reconnaissance** | ✅ Works | 12 RECONNAISSANCE alerts (`multi_port_scan`) from the same scan |
| **DoS** | ✅ Works | bounded `hping3` SYN burst → DOS, **CRITICAL**, risk ~94 (`syn_flood_cross_flow`) |
| **Brute force** | ❌ Does not fire | real `hydra` SSH mislabeled **DOS**; closed-port probes read as **BENIGN** |
| **ML model (standalone)** | ⚠️ Advisory only | contributed 0 real detections; previously caused false positives |

A representative live capture (80 s, mixed attacks): **3,509 packets → 366 flows →
365 alerts**, 0 pipeline failures. From the attacker: 225 PORT_SCAN, 12 RECON, 1 DOS,
4 BENIGN. The live dashboard reached ~2,700 packets / 30+ alerts during the demo.

---

## 2. Design decision: ML demoted to **advisory**

**What changed:** in `correlator.py`, Case C ("rule engine says BENIGN, ML says attack")
used to trust the ML and emit the ML's attack class. It now returns **BENIGN** — the ML
can no longer raise an alert on its own. Its prediction/confidence/top-3 are still
recorded and shown in the UI.

**Why:** on live traffic the ML model mislabels benign traffic. In testing it flagged:
- **83 false PORT_SCAN alerts** on the Ubuntu sensor's own return packets, and
- benign dashboard polling from the Windows host as PORT_SCAN / RECON / even CRITICAL DoS.

Root cause is **domain shift**: the model was trained on CICIDS2017 CSV flow statistics
but is fed `flow.py`'s live-computed features — different distributions. Letting it alert
alone produced noise, so it was demoted. The hybrid design and ML context are preserved;
the false positives are gone.

**Verification:** all `tests/test_correlator.py` and `tests/test_pipeline.py` cases pass
with the change (the "Rule=BENIGN, ML=Attack" case now asserts a BENIGN verdict with the
ML opinion retained).

**To make the ML genuinely contribute:** retrain on live-captured lab flows via
`retrain_model.py` (merges CICIDS2017 + live JSONL), so its training features match
runtime features. That is the recommended next step if the ML is to earn its place.

---

## 3. Known limitations

### Detection
- **Brute force doesn't fire.** Two causes: (1) a fast SSH brute force trips the DoS
  SYN-rate rule, which wins the `max(confidence)` tie → labeled DOS; (2) closed-port login
  probes are deliberately excluded as "refused SYN scans." Fixing it means re-working how
  BRUTE_FORCE competes with DOS/PORT_SCAN — contained to `rule_engine.py` but with
  regression risk, so it's deferred.
- **PORT_SCAN / RECONNAISSANCE overlap.** Both read the same per-source port counter with
  different thresholds (10 vs 5), so one scan surfaces under both labels. They are not
  cleanly separated.
- **Reconnaissance needs multiple hosts** (≥3 destination IPs). A single-target lab can't
  cleanly trigger `multi_host_scan`; only `multi_port_scan` fires.
- **Thresholds are lab-calibrated**, explicitly marked "initial" in `config.py`. They'd
  need re-tuning for a different network.
- **Flow-based only** — no payload inspection, so payload attacks (SQLi, XSS, malware
  delivery) are out of scope (would need DPI).

### Code / robustness (from the internal audit, `docs/NIDS_AUDIT_REPORT.md`)
- **P1 — flow timeout is creation-time based, not inactivity-based** (`flow_manager.py`):
  connections >timeout get split into fragments.
- **P2 — fragile ML label mapping** (`model.py`): assumes all 5 classes present in integer
  order 0–4; a class-imbalanced retrain could silently mislabel.
- **P3 — alert dedup overwrites combined confidence** (`alerts.py`).
- **Flow-table explosion under flood:** `hping3 --flood` (random source ports) creates
  tens of thousands of 1-packet flows and the sensor grinds for minutes. Use bounded DoS
  (fixed source port + packet count) — the demo guide does this.
- **IPv4/TCP-UDP only** (`packet_capture.py`) — IPv6 is dropped.

### Deployment
- **scikit-learn version mismatch:** model pickled with 1.5.2, Ubuntu venv runs 1.9.1 →
  `InconsistentVersionWarning` on every load. Pin the version or retrain in-environment.

---

## 4. What's solid (strengths)

- Clean five-stage pipeline with real per-stage **error isolation**.
- Strong, **explainable** rule-based detection of scans and floods (every alert names its
  rules).
- A polished **live Streamlit dashboard** that works end-to-end on a real VM lab.
- An unusually rigorous **evaluation harness** (`evaluation/`): session-level splits to
  avoid leakage, attribution audits, non-loopback validation, and many stage reports.
- Good **test coverage** and documentation-with-rationale throughout the code.

---

## 5. Future work (prioritised)

1. **Make brute-force detection work** — rework how BRUTE_FORCE competes with DOS/PORT_SCAN
   for auth-port traffic; verify each class on the live lab to avoid regressions.
2. **Retrain the ML model on live lab flows** (`retrain_model.py`) to fix domain shift, so
   it can promote from advisory to a genuine detector.
3. **Separate PORT_SCAN vs RECONNAISSANCE** cleanly (don't share the port counter / add
   per-host keying).
4. **Fix the audit items** P1 (inactivity timeout), P2 (robust label mapping), P3 (dedup
   confidence).
5. **Pin the model's scikit-learn version** or retrain in the deployment environment.
6. **Calibrate thresholds** against the real lab dataset (the evaluation reports are the
   evidence base).

---

## 6. Where the evidence lives

- Internal code audit: `docs/NIDS_AUDIT_REPORT.md`
- Evaluation methodology + results: `evaluation/` (stage reports `STAGE11_*.md`,
  `evaluation/TEST_STATUS.md`, `evaluation/results/*.json`)
- Raw captured evaluation data: `evaluation/datasets/*.jsonl` (kept as evidence; the
  external CICIDS/CSE-CIC CSVs were removed as re-downloadable — a small
  `CICIDS2017_sample.csv` is kept for quick training).
