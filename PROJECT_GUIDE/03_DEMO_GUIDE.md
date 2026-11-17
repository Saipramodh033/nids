# 03 — Demo Guide (Step by Step)

A script for presenting the live demo. Follow it top to bottom. Each step says **what to
do**, **what to say**, and **what to expect**.

---

## 0. Pre-demo checklist (do this 10 minutes before)

- [ ] Both VMs running in VirtualBox: **Ubuntu sensor** and **Kali attacker**.
- [ ] You can reach the sensor: `ping 192.168.56.107` from the host.
- [ ] You know the capture interface on Ubuntu: **`enp0s8`** (host-only NIC).
- [ ] Chrome ready on the Windows host.
- [ ] Terminals open: one SSH to Ubuntu, one SSH to Kali (or consoles).

> Lab addresses: **Ubuntu sensor `192.168.56.107`**, **Kali attacker `192.168.56.105`**
> (attacks appear from `.103`), **dashboard viewer = Windows host `192.168.56.1`**.

---

## 1. Start the dashboard on the Ubuntu sensor

On the **Ubuntu** machine:

```bash
cd ~/NIDS
sudo bash -c '.venv/bin/streamlit run dashboard.py \
  --server.address 0.0.0.0 --server.port 8501 --server.headless true \
  > ~/dashboard.log 2>&1 < /dev/null &'
```

- **Why `sudo`:** live packet capture needs root (raw-socket capability).
- **Why `0.0.0.0`:** so the Windows host browser can reach it.
- **Verify:** `curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8501/_stcore/health`
  should print `200`.

**Say:** *"Sentinel runs on the Ubuntu sensor and serves a dashboard on port 8501."*

---

## 2. Open the dashboard and start capture

In the **Windows host** browser, go to:

```
http://192.168.56.107:8501
```

On the page:
1. In **Network interface**, clear `auto` and type **`enp0s8`**.
2. Click **▶ Start capture**.

**Expect:** the status pill flips to **● CAPTURE ON** (green). The KPI row (Packets,
Flows, Alerts, Suppressed, In progress) will start updating; it refreshes every 2 seconds.

**Say:** *"It's now capturing live on the host-only interface. Right now there's only
background traffic, so no attacks yet."*

---

## 3. Run the attacks from Kali

On the **Kali** machine, run these one at a time and watch the dashboard react.

### 3a. Port scan (→ PORT_SCAN + RECONNAISSANCE)
```bash
sudo nmap -sS -T4 192.168.56.107
```
**Expect on dashboard (within a few seconds):**
- *Alerts by attack type* chart grows **PORT_SCAN** (and some **RECONNAISSANCE**).
- *Recent alerts* table fills with `192.168.56.103:xxxxx → 192.168.56.107:<many ports>`,
  attack type **PORT_SCAN**, severity **MEDIUM**, rule `cross_flow_port_scan`.

**Say:** *"One source hitting many ports on one host — the rule engine flags it as a port
scan and attributes it to the Kali attacker. Some flows also trip reconnaissance because
the two rules share the port counter."*

### 3b. DoS burst (→ DOS, CRITICAL)
```bash
sudo hping3 -S -p 80 -s 5000 -k -i u2000 -c 1000 192.168.56.107
```
(≈500 SYN/s for ~2 s, from a single source port so it stays one flow — **do not use
`--flood`**, which randomises source ports and floods the flow table.)

**Expect:** a **DOS** alert, severity **CRITICAL**, rule `syn_flood_cross_flow` /
`syn_flood_pattern`, high risk score (~90+).

**Say:** *"A high-rate SYN burst — the engine detects the flood as a DoS and scores it
CRITICAL."*

### 3c. (Optional, honest) Brute force
```bash
hydra -l testuser -P <(printf 'a\nb\nc\nd\ne\nf\n') ssh://192.168.56.107 -t 2
```
**Expect:** it will **not** produce a BRUTE_FORCE alert (it may show as DOS). This is a
**known limitation** — only run this if you want to discuss it. See the talking point
below.

---

## 4. What to show on the dashboard (the tour)

1. **Status pill** → CAPTURE ON.
2. **KPI row** → Packets climbing into the thousands, Flows, Alerts, Suppressed (dedup).
3. **Alerts by severity** + **Alerts by attack type** charts → MEDIUM/PORT_SCAN/RECON bars.
4. **Recent alerts** table → live feed, correct source→destination attribution.
5. **Click one alert** to expand its detail → shows the **explanation**, **triggered
   rules**, **Rule engine** verdict + confidence, and **ML model** verdict + top-3
   probabilities (this is where the ML shows as *advisory context*).

---

## 5. Talking points (tie it together)

- *"It's flow-based: it decides from traffic behaviour — packet rates, ports, hosts, TCP
  flags — not from packet contents."*
- *"It's hybrid: a rule engine plus a machine-learning model, fused by a correlator."*
- *"The rule engine is authoritative; the ML model is advisory — it's shown for context
  but doesn't raise alerts on its own, because on live traffic it drifts from its
  CICIDS2017 training data."*
- *"Everything runs in an isolated VirtualBox host-only lab — Kali attacks, Ubuntu senses,
  I view it from the host browser."*

---

## 6. Q&A prep (likely questions + honest answers)

**Q: Why did one port scan create both PORT_SCAN and RECONNAISSANCE alerts?**
A: The two rules share the per-source port counter with different thresholds (10 vs 5), so
a dense single-host scan crosses both; the engine keeps the higher-confidence label.

**Q: Is the ML model actually doing anything?**
A: It runs on every flow and is displayed in each alert's detail, and it can boost
confidence when it agrees with a rule. But on live traffic it mostly predicts BENIGN
(domain shift from CICIDS2017), so detections are currently rule-driven. Retraining on
live lab flows (`retrain_model.py`) is the path to making it contribute.

**Q: Why wasn't brute force detected?**
A: Class overlap — a fast SSH brute force looks like a flood, so the DoS rule wins the
confidence tie; and closed-port login probes are deliberately treated as scans. Fixing it
cleanly means re-working how brute force competes with DoS/port-scan. It's documented as
future work.

**Q: Could it run on a real network?**
A: The detection approach is sound for scans/floods, but thresholds are lab-calibrated and
it's flow-based (no payload), so it wouldn't catch payload attacks (SQLi, XSS, malware)
without deep packet inspection.

---

## 7. Teardown

- Stop attacks: they're one-shot commands; nothing to stop (or `Ctrl-C` a running one).
- Stop the dashboard on Ubuntu: `sudo pkill -f 'streamlit run dashboard.py'`.
- (The dashboard's capture stops when you click **■ Stop** or close the server.)
