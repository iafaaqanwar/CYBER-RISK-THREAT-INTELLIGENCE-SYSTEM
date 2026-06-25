<div align="center">

# 🛡️ Cyber Threat & Risk Intelligence System

### Real-Time Network Threat Detection & Automated Risk Assessment

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-3.0+-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-1.4+-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![SWI-Prolog](https://img.shields.io/badge/SWI--Prolog-Logic_AI-2C2D72?style=for-the-badge&logo=prolog&logoColor=white)](https://www.swi-prolog.org/)
[![License](https://img.shields.io/badge/License-MIT-00C853?style=for-the-badge)](LICENSE)

<br/>

*An intelligent cybersecurity platform that combines **Machine Learning**, **First-Order Logic (Prolog)**, and **AES-256 encryption** to detect, classify, and mitigate network threats in real time.*

---

[Features](#-key-features) · [Architecture](#-system-architecture) · [Installation](#-installation) · [Usage](#-usage) · [API Reference](#-api-reference) · [Project Structure](#-project-structure) · [Team](#-team)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [System Architecture](#-system-architecture)
- [AI & Intelligence Components](#-ai--intelligence-components)
- [Tech Stack](#-tech-stack)
- [Installation](#-installation)
- [Usage](#-usage)
- [API Reference](#-api-reference)
- [Project Structure](#-project-structure)
- [Dataset](#-dataset)
- [Security Architecture](#-security-architecture)
- [Team](#-team)
- [License](#-license)

---

## 🔍 Overview

The **Cyber Threat & Risk Intelligence System** is a full-stack cybersecurity platform that provides real-time network traffic analysis, automated threat detection, and intelligent risk assessment. It integrates three core AI paradigms:

| Paradigm | Technology | Role |
|---|---|---|
| **Machine Learning** | KNN / Naive Bayes (scikit-learn) | Classify network packets as normal or anomalous |
| **Logic-Based AI** | SWI-Prolog Knowledge Base | Diagnose threat types, assign risk levels, generate mitigations |
| **Cryptographic Security** | AES-256-GCM Encryption | Protect all threat logs in a Zero Trust Secure Vault |

The system features a stunning real-time dashboard with live packet capture visualization, threat analytics charts, an encrypted log vault, and automated PDF/HTML incident report generation.

---

## ✨ Key Features

### 🔬 Dual Analysis Modes
- **PCAP File Upload** — Upload `.pcap`, `.pcapng`, or `.cap` files for batch analysis of up to 10,000 packets
- **Live Packet Capture** — Real-time WebSocket-powered packet stream with instant threat detection

### 🤖 Machine Learning Classification
- Trained KNN classifier on the **NSL-KDD** dataset (industry-standard network intrusion dataset)
- Automated feature extraction, encoding, and scaling pipeline
- Supports both **K-Nearest Neighbors** and **Gaussian Naive Bayes** models
- Confidence-scored predictions with probability estimates

### 🧠 Prolog Logic Engine
- **200+ First-Order Logic rules** covering 11 attack categories
- Automated threat diagnosis: `Protocol × Port × Payload → Threat → Risk → Mitigation`
- Detects: DDoS, Port Scans, SQL Injection, XSS, Brute Force, DNS Tunneling, C2 Beacons, Data Exfiltration, MITM, Malware Communication
- Python fallback engine ensures functionality even without SWI-Prolog installed

### 🔐 Zero Trust Secure Vault
- All threat logs encrypted with **AES-256-GCM** authenticated encryption
- **PBKDF2-HMAC-SHA256** key derivation (100,000 iterations)
- Unique nonce and salt per encryption operation
- SQLite database with WAL mode for concurrent read performance

### 📊 Real-Time Dashboard
- Cyberpunk-themed dark UI with glassmorphism design
- Live packet stream with color-coded anomaly highlighting
- Interactive threat analytics charts and statistics
- Risk level distribution, threat type breakdown, and timeline visualization

### 📄 Automated Incident Reports
- Professional PDF reports via WeasyPrint (HTML fallback available)
- Includes: incident overview, network details, ML classification, mitigation recommendations
- Styled dark-theme reports with risk-level color coding

### 🎯 Threat Coverage

| Category | Risk Level | Example Indicators |
|---|---|---|
| DDoS (SYN/UDP/ICMP/HTTP Flood) | 🔴 Critical | SYN flags, high packet rate |
| SQL Injection | 🔴 Critical | `SELECT`, `UNION`, `' OR 1=1` patterns |
| C2 Beacon | 🔴 Critical | Outbound to ports 4444/5555 |
| Data Exfiltration | 🔴 Critical | Large outbound transfers |
| MITM Attack | 🔴 Critical | ARP spoofing, SSL stripping |
| Brute Force | 🟠 High | Repeated auth on SSH/RDP |
| XSS Attack | 🟠 High | `<script>`, `javascript:` payloads |
| Malware Communication | 🟠 High | Known malware signatures |
| DNS Tunneling | 🟠 High | Oversized DNS queries (>512 bytes) |
| Port Scanning | 🟡 Medium | SYN/FIN/XMAS/NULL scans |
| Unknown Threat | 🟢 Low | Unclassified anomalous traffic |

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        FRONTEND LAYER                           │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐  │
│  │ Landing Page │  │  Dashboard   │  │  Real-Time Charts     │  │
│  │  (Login UI)  │  │  (Widgets)   │  │  (Chart.js/WebSocket) │  │
│  └──────────────┘  └──────────────┘  └───────────────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│                     FLASK + SOCKETIO SERVER                      │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌───────────┐ │
│  │ REST API   │  │ WebSocket  │  │ File Upload│  │  Report   │ │
│  │ Endpoints  │  │ Handler    │  │ Handler    │  │ Generator │ │
│  └─────┬──────┘  └─────┬──────┘  └─────┬──────┘  └─────┬─────┘ │
├────────┼────────────────┼──────────────┼────────────────┼───────┤
│        │      INTELLIGENCE ENGINE      │                │       │
│  ┌─────▼──────────────────────────────▼─────┐    ┌─────▼─────┐ │
│  │         ML Classification Pipeline       │    │  Prolog   │ │
│  │  ┌─────────┐ ┌────────┐ ┌──────────────┐│    │ Knowledge │ │
│  │  │ Feature │→│ Scaler │→│ KNN / NB     ││    │   Base    │ │
│  │  │ Extract │ │(Std)   │ │ Classifier   ││    │ (200+ FOL │ │
│  │  └─────────┘ └────────┘ └──────────────┘│    │   Rules)  │ │
│  └──────────────────────────────────────────┘    └───────────┘ │
├─────────────────────────────────────────────────────────────────┤
│                      SECURITY LAYER                             │
│  ┌───────────────────┐  ┌──────────────────────────────────────┐│
│  │ AES-256-GCM       │  │ SQLite Vault (WAL Mode)             ││
│  │ Encryption Module │──│ Encrypted threat logs + metadata    ││
│  │ (PBKDF2 KDF)      │  │ Indexed by risk_level & timestamp  ││
│  └───────────────────┘  └──────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

---

## 🧪 AI & Intelligence Components

### 1. Machine Learning Pipeline (`train_model.py`)

```
NSL-KDD CSV ──→ Preprocessing ──→ Encoding ──→ Scaling ──→ KNN/NB Training ──→ model.pkl
                  (dropna)      (LabelEncoder) (StandardScaler)   (k=5)
```

- **Dataset**: NSL-KDD (Network Security Laboratory - Knowledge Discovery in Databases)
- **Features**: 41 network traffic features (protocol, service, flag, duration, bytes, etc.)
- **Target**: Multi-class classification (normal, DoS, Probe, R2L, U2R)
- **Split**: 75% training / 25% testing with stratified sampling
- **Export**: Serialized pipeline (`model.pkl`) with model, scaler, encoders, and label mapping

### 2. Prolog Knowledge Base (`knowledge_base.pl`)

```prolog
% Master Diagnosis Rule (First-Order Logic)
diagnose(Protocol, DstPort, PayloadIndicator,
         diagnosis(ThreatName, RiskRating, MitigationAction)) :-
    threat_type(Protocol, DstPort, PayloadIndicator, ThreatName),
    risk_level(ThreatName, RiskRating),
    mitigation(ThreatName, MitigationAction).
```

The knowledge base implements a **three-stage inference chain**:
1. **Threat Classification** — Maps `(Protocol, Port, Payload)` → `ThreatName`
2. **Risk Assessment** — Maps `ThreatName` → `RiskRating` (critical/high/medium/low)
3. **Mitigation Generation** — Maps `ThreatName` → detailed countermeasure recommendations

### 3. Encryption Module (`encryption.py`)

```
Passphrase ──→ PBKDF2 (100K iterations) ──→ AES-256 Key
                                               │
Plaintext JSON ──→ AES-GCM Encrypt ──→ Ciphertext + Auth Tag
                      (96-bit nonce)
```

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Backend** | Python 3.10+, Flask 3.0 | Web server & REST API |
| **Real-Time** | Flask-SocketIO + Eventlet | WebSocket live packet streaming |
| **ML Engine** | scikit-learn, pandas, NumPy | KNN/Naive Bayes classification |
| **Logic AI** | SWI-Prolog + PySwip | First-Order Logic threat reasoning |
| **Packet Parsing** | PyShark (TShark/Wireshark) | `.pcap` file & live capture parsing |
| **Encryption** | cryptography (AES-256-GCM) | Zero Trust log encryption |
| **Database** | SQLite3 (WAL mode) | Encrypted threat log vault |
| **Reports** | WeasyPrint | PDF incident report generation |
| **Frontend** | HTML5, CSS3, JavaScript | Cyberpunk-themed dashboard UI |
| **Environment** | python-dotenv | Secure configuration management |

---

## 🚀 Installation

### Prerequisites

| Requirement | Version | Required |
|---|---|---|
| Python | 3.10+ | ✅ Yes |
| SWI-Prolog (x64) | 9.x | ⚠️ Optional (fallback available) |
| Wireshark/TShark | 4.x | ⚠️ Optional (for live capture/pcap) |
| GTK3 Runtime | Latest | ⚠️ Optional (for PDF reports) |

### Step 1: Clone the Repository

```bash
git clone https://github.com/your-username/cyber-threat-risk-intelligence-system.git
cd cyber-threat-risk-intelligence-system
```

### Step 2: Create a Virtual Environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Configure Environment Variables

Create a `.env` file in the project root (or modify the existing one):

```env
# AES-256 Encryption Key (change in production!)
CYBER_VAULT_KEY=CyberRisk-ThreatIntel-ZeroTrust-2026

# Flask Secret Key
FLASK_SECRET=cyber-risk-intelligence-flask-secret-2026

# Flask Debug Mode (set to 0 in production)
FLASK_DEBUG=1
```

### Step 5: Train the ML Model

```bash
python train_model.py
```

This will:
- Auto-discover CSV datasets in the `data/` directory
- Preprocess and encode features
- Train the KNN classifier (k=5)
- Export the pipeline to `model.pkl`

### Step 6: Launch the Application

```bash
python app.py
```

The server starts at **http://127.0.0.1:5005**

---

## 💻 Usage

### 🌐 Web Dashboard

1. Navigate to `http://127.0.0.1:5005` in your browser
2. The **Landing Page** presents the system overview and team information
3. Click **"Launch Dashboard"** to access the main threat intelligence dashboard

### 📁 PCAP File Analysis

1. Go to the **Dashboard** → **Upload PCAP** section
2. Upload a `.pcap`, `.pcapng`, or `.cap` file (max 100 MB)
3. The system analyzes each packet through the ML → Prolog pipeline
4. View results: total packets, anomalies detected, threat details, and timeline chart

### 📡 Live Capture Mode

1. Go to the **Dashboard** → **Live Capture** section
2. Select a network interface (or use default)
3. Click **"Start Capture"** to begin real-time monitoring
4. Packets stream via WebSocket with instant anomaly detection
5. Click **"Stop Capture"** to end the session

### 🔒 Secure Vault

- All detected threats are automatically encrypted and stored in the SQLite vault
- View logged threats in the **Threat Logs** section of the dashboard
- Download individual incident reports as PDF or HTML

---

## 📡 API Reference

### System Status
```
GET /status
```
Returns component availability flags (ML model, Prolog, PyShark, capture status).

**Response:**
```json
{
  "ml_model_loaded": true,
  "prolog_ready": true,
  "pyshark_available": true,
  "capture_active": false,
  "timestamp": "2026-06-25T14:00:00"
}
```

---

### Upload PCAP File
```
POST /upload
Content-Type: multipart/form-data
Field: pcap_file
```
Analyzes a `.pcap` file and returns classification results.

**Response:**
```json
{
  "filename": "capture.pcap",
  "total_packets": 500,
  "normal_packets": 420,
  "anomalous_packets": 80,
  "threats": [
    {
      "packet_no": 12,
      "src_ip": "185.220.101.45",
      "dst_ip": "192.168.1.5",
      "protocol": "tcp",
      "dst_port": 80,
      "prediction": "anomaly",
      "confidence": 0.94,
      "threat_type": "ddos",
      "risk_level": "critical",
      "mitigation": "Deploy rate limiting and SYN cookies..."
    }
  ],
  "packet_timeline": [...]
}
```

---

### Retrieve Threat Logs
```
GET /logs
```
Returns all decrypted threat log entries from the secure vault.

**Response:**
```json
{
  "logs": [
    {
      "id": 1,
      "src_ip": "185.220.101.45",
      "threat_type": "ddos",
      "risk_level": "critical",
      "timestamp": "2026-06-25T14:00:00",
      "created_at": "2026-06-25 14:00:00"
    }
  ]
}
```

---

### Generate Incident Report
```
GET /report/<log_id>
```
Downloads a PDF or HTML incident report for a specific threat log entry.

---

### List Network Interfaces
```
GET /interfaces
```
Returns available network interfaces detected via TShark.

---

### WebSocket Events

| Event | Direction | Description |
|---|---|---|
| `start_capture` | Client → Server | Starts live packet capture |
| `stop_capture` | Client → Server | Stops live packet capture |
| `packet_data` | Server → Client | Emits classified packet data |
| `capture_status` | Server → Client | Emits capture status updates |
| `capture_error` | Server → Client | Emits capture error messages |

---

## 📂 Project Structure

```
Cyber Threat & Risk Intelligence System/
│
├── app.py                    # Flask backend server (REST API + WebSocket)
├── train_model.py            # Offline ML training script (KNN / Naive Bayes)
├── knowledge_base.pl         # Prolog knowledge base (200+ FOL rules)
├── encryption.py             # AES-256-GCM encryption module
├── db_manager.py             # SQLite secure vault manager
├── report_generator.py       # PDF/HTML incident report generator
├── model.pkl                 # Trained ML pipeline (serialized)
├── threat_logs.db            # Encrypted SQLite threat log database
├── requirements.txt          # Python dependencies
├── .env                      # Environment configuration
│
├── data/                     # Training datasets
│   ├── nsl_kdd_large.csv     # NSL-KDD dataset (full)
│   └── nsl_kdd_synthetic.csv # NSL-KDD synthetic supplement
│
├── templates/                # Jinja2 HTML templates
│   ├── landing.html          # Landing/login page
│   └── index.html            # Main dashboard page
│
├── static/                   # Static frontend assets
│   ├── css/
│   │   └── style.css         # Dashboard styles (cyberpunk theme)
│   ├── js/
│   │   └── app.js            # Frontend JavaScript (charts, WebSocket, UI)
│   └── *.jpg                 # Team member photos
│
├── reports/                  # Generated incident reports (PDF/HTML)
├── Pcap files/               # Sample .pcap files for testing
│   ├── cyber_threat_500.pcap
│   ├── cyber_threat_capture.pcap
│   └── dhcp_sample.pcap
│
└── Project Report/           # Academic project documentation
```

---

## 📊 Dataset

This project uses the **NSL-KDD** dataset, an improved version of the KDD Cup 1999 dataset, widely used as a benchmark for network intrusion detection systems.

| Property | Value |
|---|---|
| **Name** | NSL-KDD |
| **Source** | Canadian Institute for Cybersecurity (UNB) |
| **Features** | 41 network traffic features + 1 label |
| **Classes** | Normal, DoS, Probe, R2L, U2R |
| **Training Split** | 75% train / 25% test (stratified) |

The `data/` directory contains:
- `nsl_kdd_large.csv` — Full dataset (~2.4 MB)
- `nsl_kdd_synthetic.csv` — Supplementary synthetic data

---

## 🔒 Security Architecture

```
                    Zero Trust Secure Vault
                    ========================

    Threat Data (JSON)
         │
         ▼
    ┌─────────────────┐
    │  JSON Serialize  │
    └────────┬────────┘
             ▼
    ┌─────────────────┐     ┌─────────────┐
    │   PBKDF2-HMAC   │◄────│  Passphrase │
    │   SHA-256        │     │  (.env)     │
    │   100K iters     │     └─────────────┘
    └────────┬────────┘
             ▼
    ┌─────────────────┐     ┌──────────────┐
    │   AES-256-GCM   │◄────│ Random Nonce │
    │   Encrypt       │     │ (96-bit)     │
    └────────┬────────┘     └──────────────┘
             ▼
    ┌─────────────────┐
    │  Base64 Encode   │
    └────────┬────────┘
             ▼
    ┌─────────────────────────────────┐
    │   SQLite DB (threat_logs.db)    │
    │   ├── Ciphertext (encrypted)   │
    │   ├── Nonce (per-record)       │
    │   ├── Salt (per-record)        │
    │   └── Metadata (plaintext)     │
    └─────────────────────────────────┘
```

### Security Highlights
- ✅ **AES-256-GCM** — Authenticated encryption (confidentiality + integrity)
- ✅ **Per-record nonce & salt** — No two records share encryption parameters
- ✅ **PBKDF2 key stretching** — 100,000 iterations resist brute-force attacks
- ✅ **WAL mode** — SQLite Write-Ahead Logging for safe concurrent access
- ✅ **Environment-based keys** — Secrets loaded from `.env`, never hardcoded in production

---

## 🤝 Team

<div align="center">

| Member | Role |
|---|---|
| **Afaaq Anwar** | Project Lead & Full-Stack Development |
| **Ahsan** | ML Pipeline & Data Engineering |
| **Arslan** | Prolog Knowledge Base & Logic AI |
| **Taimoor** | Security Architecture & Encryption |

</div>

---

## 📜 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgements

- [NSL-KDD Dataset](https://www.unb.ca/cic/datasets/nsl.html) — Canadian Institute for Cybersecurity
- [scikit-learn](https://scikit-learn.org/) — Machine Learning library
- [SWI-Prolog](https://www.swi-prolog.org/) — Logic programming engine
- [Flask](https://flask.palletsprojects.com/) — Python web framework
- [PyShark](https://github.com/KimiNewt/pyshark) — Python wrapper for TShark
- [WeasyPrint](https://weasyprint.org/) — HTML/CSS to PDF converter

---

<div align="center">

**⭐ Star this repository if you found it useful!**

Made with ❤️ by Afaaq Anwar for Cybersecurity

</div>
