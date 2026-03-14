# 🔴 ReconAI — Automated Recon & Vulnerability Scanner

![Python](https://img.shields.io/badge/Python-3.11-blue)
![Kali Linux](https://img.shields.io/badge/Platform-Kali%20Linux-red)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

> Automated penetration testing pipeline with AI-powered PDF report generation.
> Built by **Abhishek Sharma** — Offensive Security Learner | Bug Bounty Hunter

---

## 🎯 What Is ReconAI?

ReconAI is a full automated recon and vulnerability scanner that takes a target domain and runs a complete 7-stage penetration testing pipeline — then generates a professional PDF report using AI.

**One command. Full recon. Professional report.**
```bash
python3 -m backend.main target.com
```

---

## ⚡ Features

- 🔍 **Subdomain Enumeration** — Sublist3r + Amass
- 🌐 **DNS Resolution** — IP mapping + CDN detection
- 🔌 **Port Scanning** — Nmap with service detection
- 🕵️ **Tech Fingerprinting** — Server, framework, CMS detection
- 🛡️ **CVE Matching** — Real-time NVD API lookup
- ⚡ **Vulnerability Checks** — CORS, Open Redirect, Sensitive Files, Cookie Security
- 🤖 **AI Report Generation** — Groq AI (Llama3) powered analysis
- 📄 **PDF Export** — Professional pentest report

---

## 🏗️ Architecture
```
reconai/
│
├── backend/
│   ├── main.py                  ← Master controller
│   ├── scanner/
│   │   ├── subdomain.py         ← Stage 1
│   │   ├── dns_resolve.py       ← Stage 2
│   │   ├── port_scan.py         ← Stage 3
│   │   ├── tech_detect.py       ← Stage 4
│   │   ├── cve_match.py         ← Stage 5
│   │   └── vuln_check.py        ← Stage 6
│   ├── ai/
│   │   └── report_gen.py        ← Stage 7 (AI)
│   ├── pdf/
│   │   └── export.py            ← PDF Generator
│   └── database/
│       └── db.py                ← SQLite handler
│
├── reports/                     ← Generated PDF reports
├── .env                         ← API keys (never committed)
├── .gitignore
├── requirements.txt
└── README.md
```

---

## 🛠️ Installation

### Prerequisites
- Kali Linux (recommended)
- Python 3.11+
- Nmap installed

### Setup
```bash
# Clone the repo
git clone https://github.com/Abhi-Sh4rma/reconai.git
cd reconai

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install system tools
sudo apt install amass nmap -y
pip install sublist3r
```

### Configure API Keys
```bash
cp .env.example .env
nano .env
```

Add your keys:
```
GROQ_API_KEY=your_groq_api_key_here
```

Get free Groq API key at: https://console.groq.com

---

## 🚀 Usage
```bash
# Activate virtual environment
source venv/bin/activate

# Run full scan
python3 -m backend.main target.com

# Example
python3 -m backend.main example.com
```

### Sample Output
```
╔═══════════════════════════════════════════╗
║           ReconAI Security Scanner        ║
║      Automated Recon & Vuln Detection     ║
║          Built by: Abhishek Sharma        ║
╚═══════════════════════════════════════════╝

🎯 Target: example.com
🚀 Starting full recon pipeline...

[1/6] 🔍 Subdomain Enumeration
[2/6] 🌐 DNS Resolution
[3/6] 🔌 Port Scanning
[4/6] 🔎 Tech Fingerprinting
[5/6] 🛡️  CVE Matching
[6/6] ⚡ Vulnerability Checks

📄 Generate PDF Report? (yes/no): yes
✅ PDF saved to: reports/reconai_example.com_20260314.pdf
```

---

## 📊 Sample Findings

| Category | Finding | Severity |
|---|---|---|
| Subdomain | Dangling subdomain discovered | Medium |
| Port | Ports 8080/8443 open | Medium |
| Tech | Next.js + React detected | Info |
| Headers | Missing CSP, X-Frame-Options | Medium |
| CVE | 12 CVEs matched via NVD | High |
| Files | /admin panel publicly accessible | High |

---

## ⚠️ Legal Disclaimer

> This tool is for **educational purposes** and **authorized testing only**.
> Always get **written permission** before scanning any target.
> The author is not responsible for any misuse of this tool.

---

## 👨‍💻 Author

**Abhishek Sharma**
- LinkedIn:www.linkedin.com/in/abhishek-sharma-291a42250
- TryHackMe: Top 1%
- IBM Cybersecurity Certified

---

## 📜 License

MIT License — feel free to use, modify and share with attribution.
