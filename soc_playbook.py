import json
import logging
import os
import configparser
from datetime import datetime

# ====== Setup Logging ======
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "soc_playbook.log")

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# ====== Load Config ======
config = configparser.ConfigParser()
config.read("config.ini")

SIEM_API_URL = config["SIEM"].get("api_url", "")
SIEM_API_TOKEN = config["SIEM"].get("api_token", "")
FIREWALL_API_URL = config["FIREWALL"].get("api_url", "")
FIREWALL_API_TOKEN = config["FIREWALL"].get("api_token", "")

# ====== Mock Alerts (for demo) ======
MOCK_ALERTS = [
    {
        "alert_id": "A001",
        "sender_email": "phish@malicious.com",
        "urls": ["http://badlink.com"],
        "email_id": "E123",
        "source_ip": "198.51.100.10",
    },
    {
        "alert_id": "A002",
        "sender_email": "safe@company.com",
        "urls": [],
        "email_id": "E124",
        "source_ip": "203.0.113.5",
    },
    {
        "alert_id": "A003",
        "sender_email": "scam@phish.example",
        "urls": ["http://fake.com"],
        "email_id": "E125",
        "source_ip": "192.0.2.200",
    },
]

# ====== Functions ======
def query_mock_siem():
    """Simulate querying a SIEM for phishing alerts."""
    logging.info("Querying mock SIEM for phishing alerts.")
    return MOCK_ALERTS


def analyze_alert(alert):
    """Analyze alert to determine if action is needed."""
    sender = alert.get("sender_email", "").lower()
    urls = alert.get("urls", [])
    suspicious_domains = ["malicious.com", "phish.example"]

    is_suspicious = any(domain in sender for domain in suspicious_domains) or len(urls) > 0
    if is_suspicious:
        logging.info(f"Suspicious alert detected: {alert.get('alert_id')}")
        return {
            "action": "quarantine_and_block",
            "email_id": alert.get("email_id"),
            "sender": sender,
            "source_ip": alert.get("source_ip"),
        }
    return None


def quarantine_email(action_details):
    """Simulate quarantining a suspicious email."""
    try:
        logging.info(f"Simulated QUARANTINE for email {action_details['email_id']} from {action_details['sender']}")
        print(f"[DEMO] Quarantined email {action_details['email_id']} from {action_details['sender']}")
        return True
    except Exception as e:
        logging.error(f"Failed to simulate email quarantine: {str(e)}")
        return False


def block_ip_on_firewall(ip_address):
    """Simulate blocking an IP address on a firewall."""
    if not ip_address:
        logging.warning("No IP address found in alert, skipping block action.")
        return False
    try:
        logging.info(f"Simulated BLOCK action for IP: {ip_address} on firewall.")
        print(f"[DEMO] Blocked IP: {ip_address}")
        return True
    except Exception as e:
        logging.error(f"Failed to simulate IP block for {ip_address}: {str(e)}")
        return False


def main():
    logging.info("Starting SOC automation demo playbook.")
    alerts = query_mock_siem()
    if not alerts:
        logging.info("No alerts found. Exiting.")
        return

    for alert in alerts:
        action_details = analyze_alert(alert)
        if action_details:
            email_success = quarantine_email(action_details)
            ip_block_success = block_ip_on_firewall(action_details["source_ip"])

            if email_success and ip_block_success:
                logging.info(f"Successfully processed alert: {alert.get('alert_id')}")
            else:
                logging.warning(f"Failed to fully process alert: {alert.get('alert_id')}")


if __name__ == "__main__":
    main()
