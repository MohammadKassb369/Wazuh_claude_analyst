# Wazuh AI SOC Analyst (Claude-Powered)

An AI-powered SOC automation tool that integrates **Wazuh SIEM** with **Anthropic Claude AI** to automatically analyze, prioritize, and enrich security alerts in real time.

---

## 🚀 Overview

The **Wazuh Claude AI Alert Analyzer** is a security automation pipeline that transforms raw SIEM alerts into **actionable intelligence** within seconds.

It continuously monitors Wazuh alerts, sends high-risk events to Claude AI, and generates:

* 🧠 Threat summaries
* ⚔️ Attack vector analysis (MITRE ATT&CK)
* 🎯 Affected assets
* 🚨 Severity validation
* 🛠️ Immediate response actions
* 🔍 Investigation checklist
* 📊 False positive scoring

All results are indexed into **OpenSearch** and visualized directly in the **Wazuh Dashboard**.

---

## 🔥 Key Features

* 🤖 AI-powered alert analysis (Claude)
* ⚡ Real-time SOC automation
* 🧠 MITRE ATT&CK mapping
* 📊 OpenSearch dashboard integration
* 🚫 False positive likelihood scoring
* 🔍 Investigation checklist generation
* 🛡️ Incident response recommendations
* 🔁 Alert deduplication engine
* 🧩 Custom rule prioritization (100000–999999)

---

## 🏗️ Architecture

```
Wazuh Manager
   │
   ▼
alerts.json
   │
   ▼
Python AI Analyzer
   │
   ├── Claude AI (analysis)
   │
   ├── Text Reports (.txt)
   │
   └── JSON Feed (claude_analysis.json)
           │
           ▼
        Filebeat
           │
           ▼
      OpenSearch Index
           │
           ▼
    Wazuh Dashboard
```

---

## 📂 Project Structure

```
wazuh-claude-ai-analyst/
│
├── README.md
├── requirements.txt
├── LICENSE
│
├── src/
│   └── wazuh_claude_analyzer.py
│
├── config/
│   ├── filebeat/
│   │   └── claude_analysis.yml
│   └── logstash/
│       └── claude_analysis.conf
│
├── docs/
│   ├── architecture.md
│   ├── setup-guide.md
│   ├── use-cases.md
│   └── screenshots/
│
├── examples/
│   ├── sample_alert.json
│   ├── sample_analysis.json
│   └── sample_report.txt
│
└── systemd/
    └── wazuh-claude.service
```

---

## ⚙️ Installation

### 1. Clone repository

```bash
git clone https://github.com/yourusername/wazuh-claude-ai-analyst.git
cd wazuh-claude-ai-analyst
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Set Claude API key

```bash
export ANTHROPIC_API_KEY="sk-ant-xxxxxxxx"
```

### 4. Run analyzer

#### One-time analysis:

```bash
python3 src/wazuh_claude_analyzer.py --mode once
```

#### Continuous monitoring:

```bash
python3 src/wazuh_claude_analyzer.py --mode watch
```

---

## ⚡ How It Works

### 1. Alert Collection

* Reads alerts from:

```
/var/ossec/logs/alerts/alerts.json
```

### 2. Filtering Logic

Alerts are analyzed if:

* `rule.level > 8`
  OR
* Custom rule (100000–999999)

### 3. Deduplication

Uses fingerprint:

```
SHA256(rule_id + agent_id + src_ip + timestamp_minute)
```

### 4. AI Analysis

Each alert is sent to Claude AI with structured prompt.

### 5. Output Generation

#### Human-readable report:

```
/var/ossec/logs/claude_reports/alert_L*.txt
```

#### Machine-readable JSON:

```
/var/ossec/logs/claude_reports/claude_analysis.json
```

### 6. Data Pipeline

* Filebeat ships JSON → OpenSearch
* Indexed as:

```
wazuh-claude-YYYY.MM.dd
```

---

## 📊 Example AI Analysis

```
THREAT_SUMMARY:
A webshell was detected on a domain controller, indicating a critical breach attempt.

ATTACK_VECTOR:
Likely exploitation of a web application or phishing leading to MITRE T1505.003.

AFFECTED_ASSETS:
Domain controller and connected Active Directory infrastructure.

SEVERITY_ASSESSMENT:
Critical — risk of full domain compromise.

IMMEDIATE_ACTIONS:
Isolate host | Reset credentials | Scan environment

INVESTIGATION_CHECKLIST:
Check logs | Analyze traffic | Review RDP access

FALSE_POSITIVE_LIKELIHOOD:
Low
```

---

## 📸 Screenshots


```

```

---

## ⚙️ Filebeat Integration

```yaml
- type: log
  enabled: true
  paths:
    - /var/ossec/logs/claude_reports/claude_analysis.json

  json.keys_under_root: true
  tags:
    - claude-analysis
``

```
wazuh-claude-*
```

---

## 🎯 Use Cases

* SOC Tier 1 alert triage automation
* Incident response acceleration
* Threat hunting enrichment
* Alert fatigue reduction
* AI-assisted SOC workflows

---

## 🧠 Advanced Features

* 🔁 Alert deduplication (hash-based)
* 🧩 Custom rule handling
* 📊 False positive scoring (Low / Medium / High)
* 📡 Structured JSON for dashboards
* 🧠 Context-aware AI analysis
* ⚡ Near real-time processing

---

## 🛠️ Systemd Service (Optional)

```ini
[Unit]
Description=Wazuh Claude AI Analyzer

[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/wazuh_claude_analyzer.py --mode watch
Restart=always

[Install]
WantedBy=multi-user.target
```

---

## 🔐 Security Notes

* Protect your API key
* Restrict access to log files
* Use TLS for OpenSearch in production
* Validate AI outputs before automated response

---

## ⚠️ Disclaimer

This tool is intended for **defensive cybersecurity purposes only**.
Do not use it for unauthorized activities.

---

## 📜 License

MIT License

---

## 👨‍💻 Author

**Kassab Mohammad**
Cybersecurity Engineer | SOC Automation | Threat Detection

---

## ⭐ Contributing

Contributions are welcome!

* Fork the repo
* Create a feature branch
* Submit a PR

---

---

## ⭐ If you like this project
Donate me :BTC: bc1qa32n5szlqdjglq03ytxpfglyt77f5u74premfn

