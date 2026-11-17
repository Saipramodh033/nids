# 01 — What It Does (The Full Picture)

## The problem it solves

Networks are constantly probed and attacked. A **Network Intrusion Detection System
(NIDS)** sits on the network, watches the traffic, and raises alerts when it sees
behaviour that looks like an attack — so a defender can react. Sentinel is a working,
end-to-end NIDS built to detect the most common **network-behavioural** attacks in a
controlled lab, and to show them on a live dashboard.

"Behavioural" is the key word: Sentinel decides *from how traffic behaves* — how many
packets, how fast, to how many ports/hosts, with which TCP flags — **not** from reading
the contents of the packets. This is called **flow-based** detection.

---

## The end-to-end story (what actually happens to a packet)

```
①  A packet arrives on the wire (e.g. a SYN from Kali to Ubuntu port 22).
        │
②  packet_capture.py (Scapy) parses it: source/dest IP, source/dest port,
   protocol, TCP flags, size, timestamp  → a small dict of packet info.
        │
③  flow_manager.py decides which FLOW this packet belongs to. A "flow" is one
   conversation, identified by the canonical 5-tuple
   (src_ip, dst_ip, src_port, dst_port, protocol). Both directions map to one flow.
        │
④  flow.py updates that flow's running statistics: packet/byte counts per
   direction, TCP flag counters (SYN/ACK/FIN/RST/PSH), duration, packet-size stats.
        │
⑤  When a flow completes or times out, flow.get_features() produces an
   18-number feature vector (the canonical schema in features.py).
        │
        ├─────────────────────────────┐
        ▼                             ▼
⑥a rule_engine.py                 ⑥b model.py
   applies threshold/stateful        runs the trained RandomForest on the
   rules (DoS, port scan, brute       18 features → predicts a class +
   force, recon). Returns a rule      confidence + per-class probabilities.
   prediction + confidence +
   the names of triggered rules.
        └──────────────┬──────────────┘
                       ▼
⑦  correlator.py FUSES the two results into one DetectionResult.
   (The rule engine is authoritative; the ML model is advisory — see below.)
                       │
⑧  risk_scorer.py maps the verdict + confidence to a 0–100 risk score
   and a severity (INFORMATIONAL / LOW / MEDIUM / HIGH / CRITICAL).
                       │
⑨  alerts.py creates an Alert record (with explanation, rule/ML details,
   feature snapshot), de-duplicates repeats, and rate-limits noisy sources.
                       │
⑩  dashboard.py (Streamlit "Sentinel") shows live KPIs, charts, and a
   table of recent alerts that refreshes every 2 seconds.
```

`pipeline.py` is the conductor that runs steps ③–⑨ for every completed flow, with
per-stage error handling so one bad flow can't crash the system. A background
`ProcessingWorker` thread lets capture and processing run independently.

---

## The attack classes it knows

Sentinel classifies every flow into one of **five** classes:

| Class | Attacker's goal | Example | What it looks like on the wire |
|-------|-----------------|---------|--------------------------------|
| **BENIGN** | (normal traffic) | web browsing, SSH session | normal packet/flag mix |
| **RECONNAISSANCE** | map the network | `nmap -sn`, multi-host sweep | one source touching **many hosts** |
| **PORT_SCAN** | find open services on a host | `nmap -sS` | one source touching **many ports** on one host, SYN-only probes |
| **BRUTE_FORCE** | guess credentials | `hydra ssh` | repeated short connection attempts to an **auth port** (22/23/445…) |
| **DOS** | crash / overload a service | `hping3 --flood` | very high packet rate / SYN flood |

> **Reconnaissance vs Port scan:** port scanning is a *specific technique within*
> reconnaissance. Sentinel splits them by scope — **many ports on one host → PORT_SCAN**,
> **many hosts → RECONNAISSANCE**. Because both rules share the per-source port counter
> with different thresholds, a dense single-host scan can surface under *both* labels.
>
> **DoS vs Brute force:** completely different goals (take-down vs break-in). They only
> look alike because a *fast* brute force resembles a flood — which is exactly why the
> current engine mislabels real SSH brute force as DoS (see file 04).

---

## The two detectors and how they combine

Sentinel is a **hybrid** system — two detectors look at the same 18 features:

**1. Rule engine (`rule_engine.py`)** — hand-written, explainable thresholds and
cross-flow state (e.g. "≥10 unique ports from one source in 10 seconds → port scan").
Strong on the loud, well-understood attacks. Every alert says *which* rule fired.

**2. ML model (`model.py`)** — a `StandardScaler` + `RandomForestClassifier` trained on
the public **CICIDS2017** dataset. Predicts a class and probabilities from the same 18
features. Meant to catch patterns the rules don't encode.

**The correlator (`correlator.py`)** combines them. The rule engine is treated as
**authoritative**; the ML model is **advisory**:

- If a rule fires and the ML **agrees** → confidence is boosted.
- If a rule fires and the ML disagrees → the **rule's** verdict stands.
- If **no rule fires** but the ML alone cries "attack" → the verdict stays **BENIGN**
  (the ML opinion is recorded and shown, but it does **not** raise an alert by itself).

That last point is a deliberate design choice made after live testing: on live lab
traffic the ML model mislabels benign traffic (domain shift from its CICIDS2017 training
data), so letting it alert alone produced false positives. Demoting it to advisory keeps
the hybrid design and the ML context in the UI while removing the false alarms. Full
reasoning, and how to make the ML genuinely contribute (retraining on live flows), is in
file 04 and `02_ARCHITECTURE.md`.

---

## Inputs and outputs

- **Input:** live packets from a network interface (via Scapy), **or** an uploaded
  `.pcap`/`.pcapng` replayed through the same pipeline.
- **Output:** alerts (in-memory store) with attack type, severity, risk score, source→
  destination, triggered rules, rule/ML confidences, and a human-readable explanation —
  surfaced on the Streamlit dashboard (KPIs, charts, recent-alerts table, alert detail).

---

## What it detects well — and what it doesn't (short version)

- ✅ **Port scan, reconnaissance, DoS** — detected reliably and verified live.
- ⚠️ **ML model** — runs and is displayed, but currently contributes no detections on
  live traffic (advisory only).
- ❌ **Brute force** — does not fire in practice; real SSH brute force is mislabeled DoS.

See **`04_STATUS_AND_LIMITATIONS.md`** for the measured evidence and the reasons.
