# 🪤 APKCaptor
### AI-Powered Malicious APK Detection for Banking Security Teams

APKCaptor is a Generative AI-powered malware analysis system that automatically analyzes suspicious Android APK files and identifies malicious behavior. Built for banks and financial institutions to detect fraudulent mobile applications distributed via WhatsApp, SMS, phishing links, and other channels.

---

## 🌐 Live Demo
👉 [Try APKCaptor here](https://apkcaptor.streamlit.app)

---

## 🎯 Problem Statement
Fraudsters increasingly distribute malicious mobile applications (APKs) to steal customer credentials, access sensitive information, and perform unauthorized financial transactions. Manual analysis is complex, time-consuming, and dependent on skilled cybersecurity experts.

**APKCaptor solves this by analyzing a suspicious APK in minutes — not hours.**

---

## ⚙️ How It Works
Upload APK → Static Analysis → VirusTotal Check → Risk Scoring → AI Interpretation → Threat Report

| Step | Module | What it does |
|---|---|---|
| 1 | `apkcaptor_static.py` | Extracts permissions, APIs, suspicious code patterns |
| 2 | `apkcaptor_vt.py` | Checks SHA256 hash against 70+ antivirus engines |
| 3 | `apkcaptor_scorer.py` | Calculates risk score 0-100 with severity label |
| 4 | `apkcaptor_ai.py` | Gemini AI interprets findings and writes threat summary |
| 5 | `apkcaptor_report.py` | Generates downloadable HTML threat report |
| 6 | `apkcaptor.py` | Streamlit web interface |

---

## 🔍 Features
- **Static Analysis** — Scans permissions, hardcoded IPs, encryption patterns, overlay attack indicators
 **VirusTotal Integration** — Cross-references APK hash against 70+ antivirus engines
- **AI-Powered Interpretation** — Gemini 2.5 Flash explains findings in plain English
- **Risk Scoring** — 0-100 score with CRITICAL / HIGH / MEDIUM / LOW severity
- **Threat Report** — Downloadable HTML report with IOCs and recommended actions
- **Bank-Ready UI** — Simple upload interface usable by non-technical fraud teams

---

## 🛡️ What It Detects
- Overlay attacks (fake login screens over banking apps)
- SMS interception (OTP theft)
- Keylogging via Accessibility Services
- Data exfiltration to C2 servers
- Banking trojans and credential stealers

---

## 🚀 Run Locally

### Prerequisites
- Python 3.11+
- Gemini API Key (free at aistudio.google.com)
- VirusTotal API Key (free at virustotal.com)

### Setup

```bash
git clone https://github.com/tanishkaj-26/APKCaptor.git
cd APKCaptor
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```
Create a `.env` file:
GEMINI_API_KEY=your-gemini-key

VIRUSTOTAL_API_KEY=your-virustotal-key

Run:
```bash
streamlit run apkcaptor.py
```

---


## 🧠 Tech Stack
| Component | Technology |
|---|---|
| Frontend | Streamlit |
| Static Analysis | Androguard |
| Threat Intelligence | VirusTotal API |
| AI Analysis | Google Gemini 2.5 Flash |
| Report Generation | HTML/CSS |
| Language | Python 3.12 |

---

## 📁 Project Structure

```
apkcaptor/
├── apkcaptor.py
├── apkcaptor_static.py
├── apkcaptor_vt.py
├── apkcaptor_scorer.py
├── apkcaptor_ai.py
├── apkcaptor_report.py
├── requirements.txt
└── .env
```

## 👩‍💻 Built By
**Tanishka** — Built as part of a cybersecurity + AI project targeting banking fraud prevention.

---

## ⚠️ Disclaimer
APKCaptor is intended for authorized cybersecurity research and fraud prevention purposes only.