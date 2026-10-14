# Trojan Horse Attack Simulation & SIEM Dashboard

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white)
![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)
![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white)
![Recharts](https://img.shields.io/badge/Recharts-222222?style=for-the-badge&logo=recharts&logoColor=white)
![Tkinter](https://img.shields.io/badge/Tkinter-4B8BBE?style=for-the-badge&logo=python&logoColor=white)
![Cryptography](https://img.shields.io/badge/Cryptography-SHA--256_%2F_AES--256-blueviolet?style=for-the-badge)

A full-stack cybersecurity simulation designed for educational, defensive security, and incident response research. It demonstrates how a disguised "System Cleaner" utility (the social engineering Trojan) executes a silent ransomware-style encryption attack, while a **Behavioral Monitoring Engine** and a **Real-Time SIEM SOC Dashboard** track propagation, calculate threat scores, and maintain a **tamper-evident SHA-256 cryptographically chained forensic audit log**.

---

## 🔍 System Architecture & Workflow

```
[ Victim User ] ──► Launches "System Cleaner Pro" (Fake GUI)
                            │
                            ├──► (Foreground) Simulates Registry Optimization / Cache Clean
                            └──► (Background) Silent AES-256 (Fernet) Encryption Burst
                                       │
                        ┌──────────────┴──────────────┐
                        ▼                             ▼
               [attack_log.json]              [Desktop/key.txt]
                 (Raw Telemetry)            (Ransomware Recovery Key)
                        │
                        ▼
            [monitor/audit_log.py]
      Tamper-Evident SHA-256 Hash Chain
    Canonical JSON Serialization (RFC 8785)
                        │
                        ▼
             [Flask API Server :3600]
     Serves Analysis, Raw Logs, & Forensic API
                        │
                        ▼
         [React SIEM SOC Dashboard :5173]
 ┌───────────────────────────────────────────────┐
 │ 1. Real-Time Threat Telemetry & Risk Scoring  │
 │ 2. Non-Cumulative Burst Intensity Graph      │
 │ 3. Cryptographic Chain Integrity Verifier     │
 │ 4. Interactive Tampering Demonstration Sandbox │
 └───────────────────────────────────────────────┘
```

---

## ✨ Key Features & Upgrades

### 1. Social Engineering Trojan (Fake Utility App)
- **Polished Tkinter GUI**: Disguised as "System Cleaner Pro 2026" with interactive options: *Quick Scan*, *Deep Clean*, and *Optimize Registry*.
- **Silent Asynchronous Payload**: Moves an indeterminate progress bar with fake diagnostic logs while spawning a background thread executing rapid encryption on target directories.
- **Ransomware Transition**: Switches into a high-visibility ransomware lock screen demanding the AES recovery key.
- **Hardened Decryption Validation**: Validates the recovery key against all locked files; refuses restoration and alerts if an invalid or corrupted key is supplied.

### 2. Behavioral Detection Engine & SIEM Analytics
- **Non-Cumulative Event Burst Analysis**: Tracks individual event spikes per second without cumulative distortion.
- **Dynamic Risk Scoring**: Deterministically calculates threat levels (0–100%) and categorizes alerts (**LOW**, **MEDIUM**, **HIGH**) based on:
  - Unique affected file counts
  - Peak 5-second encryption burst density
  - System error rates
- **Real-Time Telemetry Streaming**: Low-latency log ingestion streamed to security operations center analysts.

### 3. Cryptographic Forensics & Tamper-Evident Audit Logging
- **SHA-256 Hash Chaining**: Every security event record is cryptographically bound to its predecessor via `prev_hash` starting from a static Genesis Block (`00000000000000000000000000000000`).
- **Deterministic Canonical Serialization**: Ensures payload integrity and prevents hash mismatch anomalies caused by key order or whitespace formatting.
- **Continuous Integrity Verification**: Independent mathematical recalculation across every node in the chain to immediately flag:
  1. Payload modification (e.g., altered filenames, timestamps, or status)
  2. Stored hash corruption or forged digest insertion
  3. Intermediate record deletion (broken link in the chain)
  4. Record reordering or replay attacks
- **Dual-Mode Forensic Console**:
  - **Live Production Audit Log**: Real-time cryptographic ledger of live endpoint actions with verification badges and inspection modals.
  - **Interactive Tampering Sandbox**: An isolated simulation environment allowing security analysts to deliberately mutate payloads, corrupt hashes, or reorder records, observing immediate real-time forensic detection and one-click clean state restoration.

---

## 🏗️ Project Structure

| Path | Description |
| :--- | :--- |
| `app/main_app.py` | Tkinter-based "System Cleaner Pro" Trojan and Ransomware GUI. |
| `trojan/attack.py` | Core encryption engine (Fernet AES-256), decryption module, and key manager. |
| `trojan/utils.py` | Path configurations, key generation routines, and environment paths. |
| `trojan/logger.py` | Synchronous telemetry logger dispatching to disk and audit chain. |
| `trojan/data/` | Data store for raw telemetry (`attack_log.json`) and audit logs. |
| `monitor/detector.py` | Behavioral detection engine, burst calculation, and risk scoring logic. |
| `monitor/logs_reader.py`| File stream reader for parsing attack telemetry. |
| `monitor/audit_log.py` | **(New)** Cryptographic audit logging engine, SHA-256 chaining, and verification algorithms. |
| `backend/server.py` | Flask REST API serving SIEM metrics, telemetry streams, and forensic verification endpoints. |
| `frontend/` | React (Vite) SIEM SOC Dashboard with Tailwind CSS, Recharts, and Lucide icons. |
| `frontend/src/components/AuditForensics.jsx` | **(New)** Interactive Cryptographic Forensics UI and Tampering Sandbox. |
| `tests/test_audit_log.py` | **(New)** Automated test suite covering 8 comprehensive cryptographic security scenarios. |

---

## 🚀 Setup & Execution Guide

### 1. Prerequisites
- Python 3.10+
- Node.js 18+ and npm

### 2. Install Dependencies
```bash
# Install Python backend dependencies
pip install -r requirements.txt

# Install frontend dashboard dependencies
cd frontend
npm install
cd ..
```

### 3. Prepare Target Environment
Create a test directory on your Desktop for safe simulation:
```bash
mkdir -p ~/Desktop/demo1
echo "Confidential Patient Record" > ~/Desktop/demo1/patient_records.txt
echo "Admin Credentials: root/pass" > ~/Desktop/demo1/credentials.json
echo "Financial Ledger 2026" > ~/Desktop/demo1/ledger.csv
```

### 4. Launch the System
Run the components in separate terminal windows:

- **Terminal 1: Start SIEM Backend API (Port 3600)**
  ```bash
  python3 backend/server.py
  ```

- **Terminal 2: Start Frontend SOC Dashboard (Port 5173)**
  ```bash
  cd frontend && npm run dev
  ```
  Open `http://localhost:5173` in your browser.

- **Terminal 3: Launch the Trojan Utility App**
  ```bash
  python3 app/main_app.py
  ```

---

## 🧪 Forensic Security & Verification Test Suite

Run the automated test suite to validate the tamper-evident cryptographic chain across all 8 security scenarios:

```bash
python3 -m unittest tests/test_audit_log.py -v
```

### Test Coverage Scenarios:
1. `test_1_newly_created_audit_chain_passes_verification`: Baseline validation of authentic genesis and sequential hashes.
2. `test_2_modifying_event_causes_verification_to_fail`: Detection of payload attribute modifications.
3. `test_3_modifying_stored_hash_causes_verification_to_fail`: Detection of forged or altered digest values.
4. `test_4_deleting_record_breaks_previous_hash_link`: Detection of dropped logs or deleted intermediate entries.
5. `test_5_reordering_records_is_detected`: Detection of chronological replay or reordered logs.
6. `test_6_empty_audit_log_handled_correctly`: Edge-case testing of empty log states.
7. `test_7_malformed_input_does_not_crash_service`: Graceful exception handling on corrupt JSON strings.
8. `test_8_demonstration_reset_and_clean_chain_passes`: End-to-end sandbox lifecycle (tamper -> failure detection -> clean reset -> pass).

---

## 🌐 API Reference

| Endpoint | Method | Description |
| :--- | :---: | :--- |
| `/logs` | `GET` | Fetches raw chronological attack telemetry logs. |
| `/analysis` | `GET` | Computes burst density, risk score, duration, and alert level. |
| `/audit/records` | `GET` | Retrieves production audit records with real-time chain verification status. |
| `/audit/verify` | `GET/POST` | Independently recalculates every SHA-256 hash across the chain. |
| `/audit/demo` | `GET` | Fetches the current state of the isolated demonstration sandbox. |
| `/audit/demo/tamper`| `POST` | Injects deliberate tampering (`modify_event`, `modify_hash`, `delete_record`, `reorder_records`). |
| `/audit/demo/reset` | `POST` | Restores the demonstration sandbox to an authentic, valid state. |
| `/audit/demo/verify`| `GET/POST` | Re-verifies the sandbox chain integrity. |

---

## 🛡️ Security Disclaimer

> [!CAUTION]
> This software is intended **STRICTLY FOR EDUCATIONAL AND RESEARCH PURPOSES**.
> - It is designed to operate locally on an isolated, user-defined test folder (`~/Desktop/demo1`).
> - It possesses **no** network propagation, privilege escalation, persistence, or rootkit capabilities.
> - Always run cybersecurity simulations in safe, isolated virtual machines or development environments.

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
