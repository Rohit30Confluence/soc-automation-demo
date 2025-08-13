# SOC Automation Demo Playbook

## Overview
This is a Python-based demo SOC automation playbook that simulates real-world phishing alert handling. It demonstrates:

- Detecting suspicious emails from mock alerts.
- Quarantining suspicious emails.
- Blocking malicious IP addresses on a simulated firewall.
- Logging all actions for audit and demo purposes.

This project is designed as a **demo** to show end-to-end SOC workflow automation.

---

## Features
1. **Simulated SIEM Alerts:** Pulls mock phishing alerts from a JSON-like data source.
2. **Automated Analysis:** Detects phishing attempts based on sender email domains and URLs.
3. **Automated Response:** 
   - Quarantines suspicious emails.
   - Blocks source IP addresses on a simulated firewall.
4. **Logging:** Records all actions in `logs/soc_playbook.log`.

---

## Getting Started

### Prerequisites
- Python 3.9+  
- `requests` library

### Setup
1. Clone the repository:
   ```bash
   git clone <repo_url>
   cd soc-automation

