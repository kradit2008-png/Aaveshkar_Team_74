# 🛡️ Identity Shield — Quick-Start & Browser Dashboard Guide
> **Problem 4.1 / P16**: Exposure of Personal Identity Through Routine Online Sign-Ups  
> **Dashboard URL**: `http://192.168.0.120:3000` (or `http://localhost:3000`)  
> **Reading Time**: ~3 minutes | **Target Audience**: Evaluators, Hackathon Judges, and End Users

---

## ⚡ 1. The 30-Second Pitch

When you enter your personal email (`user@personal.me`) into a newsletter, trial, or coupon form, that email becomes a **Universal Foreign Key**. Data brokers and ad networks use `SHA256(email)` to link your health, finance, browsing, and purchase history across hundreds of databases. When a breach happens, you cannot trace who leaked your information, and clicking "Unsubscribe" never removes you from their backups.

**Identity Shield** solves this with **cryptographic identity compartmentalization**:
- Generates unique, pseudonymous relay aliases for every website using **HMAC-SHA256**.
- **Air-gaps** your true email address—services only ever see isolated aliases.
- **Attribution Radar** detects unauthorized senders and data broker resales.
- **Single-Click Kill-Switch** severs compromised channels instantly.

```
[ Real Identity: user@personal.me ] (AIR-GAPPED & SAFE)
                 │
      ┌──────────┴──────────┐
      ▼                     ▼
[ Commercial Pod ]    [ Ephemeral Pod ] (Auto-Expires: 7/14/30 Days)
(Netflix, Amazon)     (Trials, Newsletters, Free Downloads)
      │                     │
  Verified Inbound       Data Broker Leak Attempt
  ↳ Forward Allowed      🚨 CAUGHT & KILLED IN SECONDS!
```

---

## 🌐 2. Browser Dashboard Overview (`http://192.168.0.120:3000`)

The web dashboard is a mission-control cybersecurity console built with zero external dependencies and 100% offline capability.

### 🛡️ Header & Instant Multi-Device Sync
- **LAN Address Pill**: Automatically detects and displays your machine's network IP (`http://192.168.0.120:3000`).
- **📱 Scan QR**: Generates an offline HTML5 vector QR code to open the dashboard immediately on any smartphone or tablet connected to the same Wi-Fi.
- **🔄 Reset Demo**: Restores fresh competition seed data with one click.
- **⬇ Export Vault JSON**: Downloads a complete backup of all identities and audit logs (`/api/export`).

### 📊 Real-Time Cyber HUD & Exposure Risk Gauge
- **Telemetry Ticker**: Shows relay node status (`0.0.0.0:3000`), active ciphers (`HMAC-SHA256 / AES-256`), and compliance posture (`GDPR Art. 17 / CCPA`).
- **Dynamic Metrics**:
  - **Protected Identities**: Registered vault entries.
  - **Active Forwarders**: Healthy, active email bridges.
  - **Ephemeral / Trials**: Disposable, time-limited aliases.
  - **Blocked / Leaks**: Neutralized data broker attempts.
- **Dynamic Exposure Risk Gauge**: A real-time threat meter calculated dynamically:
  $$\text{Risk Score} = (\text{Leaks} \times 28) + (\text{Commercial} \times 4) + (\text{Ephemeral} \times 2)$$
  Classified into *Minimal* (0–20%), *Moderate* (21–55%), and *High Exposure* (>55%).

### 🗺️ Compartmentalization Topology (Air-Gap Visualizer)
Interactive SVG diagram demonstrating zero-trust isolation:
- **Root Anchor**: Master identity stored safely on local hardware.
- **Tier 1 (Core)**: Critical services (Apex National Bank, GovID Health).
- **Tier 2 (Commercial)**: Vendor-bound 1-to-1 relays (Netflix, Spotify).
- **Tier 3 (Ephemeral)**: Auto-decaying trial aliases.
- **Rogue Broker Containment**: Visualizes an intercepted data resale link blocked by an active firewall shield.

---

## 🛠️ 3. Core Functional Modules in the Browser

| Module | Location | Purpose & Functionality |
| :--- | :--- | :--- |
| **⚡ Generate Alias** | Left Column (Top) | Generates HMAC-SHA256 tagged aliases (e.g., `service.hash@relay.identityshield.local`). Supports Core, Commercial, and Ephemeral tiers with custom TTL (e.g., 14 days). |
| **🔍 Leak Attribution Sandbox** | Left Column (Middle) | Tests inbound messages against registered sender domains. Flags mismatched senders (`POTENTIAL_LEAK_OR_RESALE`) and auto-triggers the kill-switch. |
| **📡 Dark Web & Broker Radar** | Left Column (Bottom) | Cross-references aliases against simulated dark web dumps and broker graphs (Acxiom, LiveRamp, Experian). |
| **📜 SOC Live Event Stream** | Left Column (Lower) | Chronological audit ledger logging cryptographic events with millisecond timestamps (`BOOT`, `HMAC_GEN`, `RELAY_OK`, `LEAK_BLOCKED`, `KILL_SWITCH`). |
| **📋 Identity Vault** | Right Column (Top) | Searchable, sortable list of all aliases with status filtering and quick action buttons. |
| **📖 Knowledge Hub & PPID Lab** | Right Column (Bottom) | Educational tabs explaining the Identity Trilemma, failure of plus-addressing, GDPR remedies, and an interactive **Pairwise Pseudonymous Identifier (PPID) Lab**. |

---

## 🚀 4. The 60-Second Live Demo Script

When evaluating or presenting the project in your browser, follow these 4 simple steps:

1. **Check the Live Console**:
   - Open `http://192.168.0.120:3000` in your browser.
   - Point out the active **LAN URL**, the **Exposure Risk Gauge**, and the **Topology Graph**.

2. **Generate a Disposable Alias**:
   - In **Generate Alias**, enter:
     - Service: `Sketchy E-Book Club`
     - Expected Domain: `sketchyebooks.com`
     - Security Tier: `Ephemeral (TTL)` $\rightarrow$ `14 Days`
   - Click **⚡ Generate Protected Address**. In $<10\text{ms}$, a unique cryptographically bounded alias is created.

3. **Simulate a Data Broker Leak**:
   - In **Leak Attribution Sandbox**, select the alias you just created.
   - In **Simulated Sender**, type: `spammer@data-broker-resale.com`.
   - Leave `Auto-trigger Kill-Switch` checked and click **🔍 Inspect Inbound Message**.
   - **Result**: 🚨 A bright red alert triggers: *Unauthorized sender domain mismatch! Forensic verdict: Provider leaked or sold your data.*

4. **Verify Route Termination & Audit Logging**:
   - Observe the alias automatically transition to `REVOKED`.
   - Check the **SOC Live Event Stream** to see the forensic breach receipt logged with timestamp.

---

## 📱 5. Mobile Experience & Cross-Device Access

- **Instant Phone Sync**: Click **📱 Scan QR** in the top header and scan the code with your phone's camera to load `http://192.168.0.120:3000` over local Wi-Fi.
- **Responsive Touch Cards**: Wide tables transform into sleek, touch-friendly mobile cards with haptic clipboard copy buttons.
- **Bottom Navigation**: Intuitive thumb navigation bar (`Vault`, `New`, `Trace`, `Guide`) with a **⚡ Floating Action Button (FAB)** for fast alias creation.
- **Per-Alias QR Codes**: Click the `📱` icon next to any alias to display a QR code specifically for pasting that email into a mobile signup form.

---

## ⚖️ 6. Compliance & Advanced Cryptography

- **GDPR Article 17 Erasure Generator**: Click **⚖️ Notice** on any revoked alias to generate a formal, pre-formatted legal erasure demand citing the unique 1-to-1 alias as forensic evidence of non-compliance.
- **🔬 PPID Cryptographic Lab**: Switch to the PPID Lab tab and test blinded email hashing:
  $$\text{PPID}_A = \text{HMAC}(\text{AccountUUID}, \text{"ServiceA:Salt"})$$
  $$\text{PPID}_B = \text{HMAC}(\text{AccountUUID}, \text{"ServiceB:Salt"})$$
  Mathematically guarantees that Service A and Service B cannot join user records even if they collude.

---

## 🏁 7. Quick Commands Cheat Sheet

| Task | Command / Action |
| :--- | :--- |
| **Launch Server** | Double-click `run.bat` or run `node server.js` |
| **Run Unit Tests** | `node tests/test_node_server.js` (or `pytest tests/`) |
| **Python CLI Generate** | `python src/identity_shield.py generate --service "Demo" --tier ephemeral --ttl 7` |
| **Python CLI Leak Trace** | `python src/identity_shield.py trace --alias "<alias>" --sender "rogue@broker.com"` |
| **Reset Demo State** | Click `🔄 Reset Demo` in the browser navbar |

---
*Identity Shield — Kalpvruksh 2.0 // Mini Hackathon 2026*  
*Local Node Server: `http://192.168.0.120:3000` | Zero Dependencies | 100% Offline Capable*
