# AIPowered-SOC-System-operation-center-Alert-investigation-Agent
An autonomous multi-agent SOC system that enriches, triages, and responds to cybersecurity alerts with zero human intervention( Prototype ).

# Smart SOC Automation & Incident Handling Framework

This project is built to solve one of the biggest challenges SOC teams face today: repetitive alert triage.  
Instead of drowning analysts in enrichment work, the system takes incoming alerts, processes them through a structured investigation pipeline, enriches data, correlates indicators, maps them to MITRE ATT&CK, and triggers intelligent playbooks for guided remediation.

The goal was simple: build something practical, reliable, and genuinely useful for real SOC teams not just another over-engineered toy.  
Every module in this repository mirrors how human analysts think and act during investigations.

## ⚡ Features

- Automated IOC enrichment (WHOIS, VirusTotal, OTX, Geolocation, ASN)
- Intelligent playbook execution (phishing, malware, auth anomalies, recon activity)
- MITRE ATT&CK mapping
- Dynamic decision-making logic
- Semi-automated remediation actions
- Clean JSON/PDF report generation
- Modular architecture for easy customization

---

## 📁 Repository Structure

SOC Autonomous Agent/
│
├── src/
│   ├── main.py
│   ├── logic_engine.py
│   ├── enrichment/
│   ├── playbooks/
│   ├── reporting/
│   └── utils/
│
├── config/
│   ├── settings.yaml
│   ├── api_keys.example.json
│
├── docs/
│   ├── PROJECT_DESCRIPTION.md
│   ├── INSTALLATION_GUIDE.md
│   ├── SYSTEM_ARCHITECTURE.md
│   ├── API_REFERENCE.md
│   ├── PLAYBOOK_DESIGN.md
│   └── REPORTING_FORMAT.md
│
├── samples/
│   ├── sample_alert.json
│   └── sample_report.pdf
│
├── .gitignore
├── LICENSE
├── README.md
└── CHANGELOG.md

## 🚀 Getting Started

### 1. Clone the Repository
bash
git clone // Repository name
cd // Project name

