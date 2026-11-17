# START HERE — NIDS "Sentinel" Project Guide

> **If you are a new reader (human or AI): read this file first.** It is the single
> entry point to understanding the whole project. Everything you need is in this
> `PROJECT_GUIDE/` folder, in reading order.

---

## What this project is, in one paragraph

**Sentinel** is a Python, flow-based **Network Intrusion Detection System (NIDS)**.
It captures live network packets (or replays a PCAP), groups them into bidirectional
**flows**, extracts 18 statistical features per flow, and runs each flow through **two
detectors in parallel** — a hand-written **rule engine** and a **machine-learning model**
(RandomForest). Their outputs are **fused** by a correlator into a single verdict, scored
for **risk/severity**, and raised as **alerts** shown on a live **Streamlit dashboard**.
It detects **reconnaissance, port scanning, brute force, and denial-of-service (DoS)**
attacks from network behaviour alone (no payload inspection).

---

## Read these in order

| # | File | What it gives you |
|---|------|-------------------|
| 00 | **`00_START_HERE.md`** (this file) | Entry point, index, the 30-second picture |
| 01 | **`01_WHAT_IT_DOES.md`** | Full plain-English picture: the problem, the end-to-end story, the attack classes, how the two detectors combine |
| 02 | **`02_ARCHITECTURE.md`** | The engineering: component & data-flow diagrams, file-by-file map, every detection rule + threshold, the correlator logic, the ML model, deployment topology |
| 03 | **`03_DEMO_GUIDE.md`** | Step-by-step script to present the live demo (commands, what to click, what to say, Q&A prep) |
| 04 | **`04_STATUS_AND_LIMITATIONS.md`** | Honest state: what works (measured live), what doesn't, known issues, the ML-advisory design decision, future work |

---

## The 30-second picture

```
Kali attacker ──network──> Ubuntu sensor (runs Sentinel) ──> Dashboard in your browser

 packets ─► flows ─► 18 features ─┬─► Rule engine ─┐
                                  └─► ML model ─────┴─► Correlator ─► Risk ─► Alert ─► Dashboard
```

- **Capture host (sensor):** Ubuntu VM `192.168.56.107`, interface `enp0s8`.
- **Attacker:** Kali VM `192.168.56.105` (routes from `192.168.56.103` on the host-only net).
- **Viewer:** Windows host browser → `http://192.168.56.107:8501`.
- **Network:** VirtualBox host-only `192.168.56.0/24` (isolated lab).

## Current status (one line each)

- ✅ **Works, verified live:** port scan, reconnaissance, DoS detection + the live dashboard.
- ⚠️ **Advisory only:** the ML model runs and is displayed but no longer raises alerts on
  its own (it was producing false positives on live traffic — see file 04).
- ❌ **Known gap:** brute-force detection does not fire in practice (class overlap with DoS /
  port-scan — see file 04). Documented as future work.

## How to run it (fast reference — full steps in `03_DEMO_GUIDE.md`)

```bash
# On the Ubuntu sensor:
cd ~/NIDS
sudo bash -c '.venv/bin/streamlit run dashboard.py --server.address 0.0.0.0 --server.port 8501 --server.headless true'
# Then open http://192.168.56.107:8501, type interface `enp0s8`, click "Start capture".

# On Kali (generate attacks):
sudo nmap -sS -T4 192.168.56.107                                 # port scan / recon
sudo hping3 -S -p 80 -s 5000 -k -i u2000 -c 1000 192.168.56.107  # DoS burst
```

## Map of the codebase (top level)

```
NIDS/
├── PROJECT_GUIDE/        ← you are here (read this first)
├── README.md             ← short public readme (points here)
├── config.py             ← all tunable thresholds (single source of truth)
├── packet_capture.py     ← Scapy capture + packet parsing
├── flow.py               ← Flow object + 18-feature computation
├── flow_manager.py       ← groups packets into flows, expires them
├── features.py           ← canonical 18-feature schema
├── rule_engine.py        ← threshold/stateful detection rules
├── model.py              ← ML model wrapper (StandardScaler + RandomForest)
├── correlator.py         ← fuses rule + ML into one verdict
├── risk_scorer.py        ← verdict → risk score + severity
├── alerts.py             ← alert creation, dedup, rate-limit, storage
├── pipeline.py           ← wires it all together; background worker
├── dashboard.py          ← Streamlit UI ("Sentinel")
├── dashboard_data.py     ← dashboard KPI/aggregation helpers
├── train_model.py        ← train the ML model from CICIDS2017
├── retrain_model.py      ← retrain on CICIDS2017 + live-captured flows
├── data_extractor.py     ← CICIDS2017 → 18-feature extraction/label mapping
├── models/               ← nids_model.joblib (shipped trained model)
├── tests/                ← unit/integration/regression tests
├── evaluation/           ← evaluation harness, stage reports, captured evidence
└── docs/                 ← audit report, notes, dashboard requirements, papers
```
