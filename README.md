# Identity Exposure Mitigation Suite
> **Problem 4.1 / P16: Exposure of Personal Identity Through Routine Online Sign-Ups**  
> **Event**: Kalpvruksh 2.0 // Mini Hackathon 2026  
> **Release**: v1.0 Production-Optimized (28/28 Automated Tests Passing)

---

### 📚 Essential Guides & Documentation
* ⚡ **[Quick-Start & Browser Guide (`EXPLANATION_SHORT.md`)](EXPLANATION_SHORT.md)** — *Short-form guide covering the live browser dashboard (`http://192.168.0.120:3000`), 60-second live demo script, and core features.*
* 🏆 **[Judges & Evaluators Guide (`EXPLANATION_FOR_JUDGES.md`)](EXPLANATION_FOR_JUDGES.md)** — *Non-technical walkthrough with plain-English analogies, 3-minute live demo script, and deep file breakdown.*
* 🗣️ **[How to Explain to Anyone (`HOW_TO_EXPLAIN_TO_ANYONE.md`)](HOW_TO_EXPLAIN_TO_ANYONE.md)** — *60-second coffee chat script and everyday Q&A.*
* 🚀 **[System Improvement Report 1.0 (`docs/IMPROVEMENT_1.0.md`)](docs/IMPROVEMENT_1.0.md)** — *Performance benchmarks, in-memory caching, SQLite WAL optimization, and test reports.*
* 🔍 **[Bug Reports (`docs/BUG_REPORT_1.0.md`)](docs/BUG_REPORT_1.0.md) & [(`docs/BUG_REPORT_2.0.md`)](docs/BUG_REPORT_2.0.md)** — *15 audited and remediated defects across mobile, desktop, and networking.*
* 📐 **[Technical Specification (`docs/problem_4_1_technical_specification.md`)](docs/problem_4_1_technical_specification.md)** — *STRIDE threat model, identity graph mathematics, and GDPR/CCPA alignment.*

---

## 1. Project Overview & Components

This suite addresses the **Identity Trilemma** (balancing *Privacy & Isolation*, *Traceability & Attribution*, *Access Continuity*, and *Convenience*):

| Component | Path | Description |
| :--- | :--- | :--- |
| **Formal Threat Model & Spec** | [`docs/problem_4_1_technical_specification.md`](docs/problem_4_1_technical_specification.md) | STRIDE analysis, data broker graph stitching mechanics, comparison of ad-hoc mitigations, and GDPR/CCPA alignment. |
| **System Improvement Report 1.0** | [`docs/IMPROVEMENT_1.0.md`](docs/IMPROVEMENT_1.0.md) | In-memory vault caching, SQLite WAL optimization, 5 B-Tree indexes, constant-time verification, and benchmarks. |
| **Executable Identity Shield Engine** | [`src/identity_shield.py`](src/identity_shield.py) | Zero-dependency Python CLI tool providing HMAC-tagged alias generation, SQLite WAL vault, TTL purge sweeps, search, and kill-switches. |
| **High-Performance Network Server** | [`server.js`](server.js) | Standalone Node.js server with in-memory caching, async atomic storage, ETag/304 static caching, and LAN IP detection. |
| **Cyber Command Web Dashboard** | [`web/templates/index.html`](web/templates/index.html) | High-tech responsive dashboard with real-time exposure risk gauge, leak attribution simulator, topology visualizer, and SOC feed. |
| **Privacy-First Database Schema** | [`database/schema_privacy_first_auth.sql`](database/schema_privacy_first_auth.sql) | Production SQL DDL demonstrating Pairwise Pseudonymous Identifiers (PPIDs), blinded email hashing (HMAC-SHA256), and automated TTL purging. |
| **Automated Test Suites** | [`tests/`](tests/) | 28 automated unit and integration tests covering Python CLI, Flask REST API, and Node.js network server (100% pass rate). |

---

## 2. Threat Model Summary (STRIDE)

Routine online registrations turn personal email addresses into persistent foreign keys across independent databases:
- **Information Disclosure / Profiling**: Third-party trackers and data brokers (Acxiom, Experian) correlate activities via `SHA256(email)`.
- **Attribution Failure**: When unsolicited spam or spear-phishing arrives, users have no technical mechanism to determine which service leaked or sold their contact information.
- **Phantom Retention**: "Unsubscribe" stops marketing emails but leaves PII indefinitely in back-end databases, backups, and analytics warehouses.

---

## 3. The 3-Tier Identity Framework

```
+-------------------------------------------------------------------------------+
| TIER 1: Core Anchor Identity (Strictly Air-Gapped)                            |
| - Financial, Government, Critical Healthcare, Master Account Recovery         |
| - Protected with FIDO2 / WebAuthn; Never entered on public web forms          |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
| TIER 2: Persistent Commercial Identities (Cryptographically Masked Relays)   |
| - SaaS subscriptions, reputable e-commerce, active services                   |
| - 1 unique pseudonymous alias per service; bi-directional forwarder           |
+-------------------------------------------------------------------------------+
                                      |
                                      v
+-------------------------------------------------------------------------------+
| TIER 3: Ephemeral / Zero-Trust Layer                                          |
| - Content gates, webinars, whitepapers, one-off trial downloads               |
| - Configurable TTL (auto-expires in 7-30 days); instant kill-switch           |
+-------------------------------------------------------------------------------+
```

---

## 4. Quickstart Guide (Identity Shield CLI)

### Requirements
* Python 3.10+ (Tested on Python 3.14 on Windows) or Node.js 16+
* Zero external pip dependencies (uses Python standard library).
* Zero external npm packages (uses native Node.js standard modules).

### Running Automated Tests
```powershell
# Run full Python automated test suite (18 tests):
python -m unittest discover -s tests -p "test_*.py"

# Run Node.js integration test suite (10 tests):
node tests/test_node_server.js
```
*Combined Result: 28 passing tests (100% pass rate, 0 failures).*

---

### CLI Commands & Examples

#### 1. Generate a New Alias
Generate a compartmentalized alias for an ephemeral newsletter subscription:
```powershell
python src/identity_shield.py generate `
  --service "TechWeekly" `
  --service-domain "techweekly.io" `
  --tier ephemeral `
  --ttl 14 `
  --domain "relay.internal"
```

#### 2. List Vault Identities
```powershell
python src/identity_shield.py list
```

#### 3. Search Identities by Keyword
Fast parameterized search across service names, domains, relay addresses, and notes:
```powershell
python src/identity_shield.py search "cloud"
```

#### 4. Inbound Attribution & Leak Detection
Trace an incoming email to verify if the sender matches the registered service:
```powershell
# Authorized message from legitimate provider:
python src/identity_shield.py trace `
  --alias "techweekly.dfc853d0e6ff10aa@relay.internal" `
  --sender "editor@techweekly.io"

# Unauthorized message from a data broker (triggers instant kill-switch):
python src/identity_shield.py trace `
  --alias "techweekly.dfc853d0e6ff10aa@relay.internal" `
  --sender "promotions@spam-harvester.com" `
  --auto-revoke
```

#### 5. Manual Kill-Switch (Revocation)
```powershell
python src/identity_shield.py revoke `
  --alias "techweekly.dfc853d0e6ff10aa@relay.internal" `
  --reason "UNSUBSCRIBE_IGNORED"
```

#### 6. Batch Purge Overdue Ephemeral Signups
Atomic sweep to transition all expired temporary signups:
```powershell
python src/identity_shield.py purge
```

#### 7. Export Vault
```powershell
python src/identity_shield.py export --out backup_vault.json
```

#### 8. Reset Demo Vault
Reset the vault to the fresh competition demonstration dataset:
```powershell
python src/identity_shield.py reset-demo
```

---

## 5. Web Console & Any-Device Network IP Support

The application includes cross-device network rendering support, allowing any phone, tablet, or laptop on the local Wi-Fi to connect.

### Option A: Launch with Node.js (Port 3000 — Recommended)
Blazingly fast standalone server with in-memory caching and sub-millisecond API response:
```powershell
# Double-click run.bat or execute:
node server.js
```
The server auto-detects your local network IP and prints:
```text
===============================================================
🛡️  IDENTITY SHIELD — NODE.JS CROSS-DEVICE NETWORK SERVER
===============================================================
[*] Status: Listening on all network interfaces (0.0.0.0:3000)
[>] Localhost (This PC):    http://localhost:3000
[>] Network IP (Any Device on your Wi-Fi / LAN):
    📱 http://192.168.0.120:3000  (Wi-Fi)
---------------------------------------------------------------
👉 Open the Network URL on your phone/tablet/laptop to connect!
===============================================================
```

### Option B: Launch with Python Flask (Port 5000)
```powershell
python web/app.py
```

### Cross-Device & Accessibility Features
- **Mobile First Responsive Design**: Wide tables automatically morph into touch-friendly cards on screens $\le 768\text{px}$ with $\ge 46\text{px}$ touch targets and haptic feedback.
- **Offline Scannable QR Code**: Open the app on your phone in 2 seconds using the built-in offline QR generator (works without external internet or Google APIs).
- **Keyboard Shortcuts**: Press `/` or `Ctrl+K` from anywhere to jump to search; press `Escape` to close modals.
- **One-Click Demo Reset**: Reset all sample data to the initial state using the header button or `/api/reset-demo`.

---

## 6. Privacy-Preserving System Design (For Service Providers)

The included schema in [`database/schema_privacy_first_auth.sql`](database/schema_privacy_first_auth.sql) demonstrates how modern applications can respect user privacy by default:
1. **Pairwise Pseudonymous Identifiers (PPID)**: Distinct client-facing identifiers per client application, eliminating cross-service data correlation.
2. **Double-Salted Blinded Hashes**: Storing `HMAC_SHA256(pepper, email || salt)` for duplicate detection and rate limiting without persisting raw email strings.
3. **Automated Storage Limitation Sweeps**: Scheduled hard deletion of expired trial registrations satisfying GDPR Article 5(1)(e) and Article 17.

---
*Created for Problem 4.1 // Kalpvruksh 2.0 Hackathon 2026.*
