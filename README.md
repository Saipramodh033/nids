# Sentinel — Network Intrusion Detection System (NIDS)

A Python, **flow-based hybrid NIDS**. It captures live network traffic (or replays a
PCAP), aggregates packets into bidirectional **flows**, extracts 18 statistical features
per flow, and detects attacks using a **rule engine + machine-learning model** fused by a
correlator. Alerts and risk scores are shown on a live **Streamlit dashboard**.

Detects **reconnaissance, port scanning, brute force, and DoS** from network behaviour
(no payload inspection).

---

## 📖 Full documentation — start here

**→ [`PROJECT_GUIDE/00_START_HERE.md`](PROJECT_GUIDE/00_START_HERE.md)**

The `PROJECT_GUIDE/` folder is the complete, self-contained explanation of this project
(written so a new reader — human or AI — can get the full picture):

| File | What it covers |
|------|----------------|
| [`00_START_HERE.md`](PROJECT_GUIDE/00_START_HERE.md) | Entry point, index, 30-second picture, codebase map |
| [`01_WHAT_IT_DOES.md`](PROJECT_GUIDE/01_WHAT_IT_DOES.md) | Full plain-English picture: the problem, the end-to-end story, attack classes, the two detectors |
| [`02_ARCHITECTURE.md`](PROJECT_GUIDE/02_ARCHITECTURE.md) | Diagrams, file-by-file map, every rule + threshold, correlator logic, ML model, deployment topology |
| [`03_DEMO_GUIDE.md`](PROJECT_GUIDE/03_DEMO_GUIDE.md) | Step-by-step live demo script (commands, what to click, what to say, Q&A) |
| [`04_STATUS_AND_LIMITATIONS.md`](PROJECT_GUIDE/04_STATUS_AND_LIMITATIONS.md) | Honest state: what works (measured live), what doesn't, known issues, design decisions |

---

## Quick start

```bash
pip install -r requirements.txt       # pandas, scapy, scikit-learn, joblib, streamlit
streamlit run dashboard.py            # open the dashboard, then Start capture or replay a PCAP
```

A trained model (`models/nids_model.joblib`) and a sample dataset
(`evaluation/datasets/CICIDS2017_sample.csv`) are included, so the dashboard runs without
training first.

### Run the live lab demo (Kali → Ubuntu)

See [`PROJECT_GUIDE/03_DEMO_GUIDE.md`](PROJECT_GUIDE/03_DEMO_GUIDE.md). In short:

```bash
# Ubuntu sensor:
sudo bash -c '.venv/bin/streamlit run dashboard.py --server.address 0.0.0.0 --server.port 8501 --server.headless true &'
# Browser → http://192.168.56.107:8501 → interface `enp0s8` → Start capture

# Kali attacker:
sudo nmap -sS -T4 192.168.56.107                                 # port scan / recon
sudo hping3 -S -p 80 -s 5000 -k -i u2000 -c 1000 192.168.56.107  # DoS burst
```

---

## Architecture at a glance

```
packets ─► FlowManager ─► Flow (18 features) ─┬─► RuleEngine ─┐
                                              └─► ML model ────┴─► Correlator ─► Risk ─► Alert ─► Dashboard
```

The rule engine is **authoritative**; the ML model is **advisory** (runs and is displayed,
but does not raise alerts on its own — see `04_STATUS_AND_LIMITATIONS.md` for why).

## Status

- ✅ Port scan, reconnaissance, DoS — detected and verified live.
- ⚠️ ML model — advisory only (domain shift vs CICIDS2017 training data).
- ❌ Brute force — does not fire in practice (documented future work).

## Requirements

- Python 3.12+ (deployment tested on 3.14)
- `pandas`, `scapy`, `scikit-learn`, `joblib`, `streamlit` (see `requirements.txt`)
- Live capture needs packet-capture permissions (root on Linux; Npcap + Admin on Windows)

## Repository layout

```
NIDS/
├── PROJECT_GUIDE/   ← complete documentation (read 00_START_HERE.md first)
├── *.py             ← core modules (see 02_ARCHITECTURE.md for the file-by-file map)
├── models/          ← trained model (nids_model.joblib)
├── tests/           ← unit / integration / regression tests
├── evaluation/      ← evaluation harness, stage reports, captured evidence
└── docs/            ← code audit, notes, dashboard requirements, reference papers
```
