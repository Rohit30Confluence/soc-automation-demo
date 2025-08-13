import logging

# Configure logging
logging.basicConfig(
    filename='soc_playbook.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Mock SIEM data with source IPs to simulate alerts
MOCK_ALERTS = [
    {"alert_id": "A001", "sender_email": "phish@malicious.com", "source_ip": "198.51.100.10"},
    {"alert_id": "A002", "sender_email": "safe@company.com", "source_ip": "203.0.113.5"},
    {"alert_id": "A003", "sender_email": "scam@phish.example", "source_ip": "192.0.2.200"}
]

def analyze_alert(alert):
    """Analyze alert for suspicious indicators."""
    suspicious_domains = ["malicious.com", "phish.example"]
    sender = alert.get("sender_email", "").lower()

    if any(domain in sender for domain in suspicious_domains):
        logging.info(f"Suspicious alert detected: {alert.get('alert_id')}")
        return alert # Return the full alert if suspicious
    return None

def quarantine_email(alert):
    """Simulate quarantining a suspicious email."""
    logging.info(f"Simulated QUARANTINE for email from {alert['sender_email']}")
    return True

def block_ip_on_firewall(alert):
    """Simulate blocking an IP address on a firewall."""
    ip = alert.get("source_ip")
    logging.info(f"Simulated BLOCK action for IP: {ip} on firewall.")
    return True

def main():
    """Main function to run the playbook."""
    logging.info("Starting SOC automation playbook.")

    for alert in MOCK_ALERTS:
        analyzed_alert = analyze_alert(alert)
        if analyzed_alert:
            quarantine_email(analyzed_alert)
            block_ip_on_firewall(analyzed_alert)
            logging.info(f"Successfully processed alert: {analyzed_alert['alert_id']}\n")

if __name__ == "__main__":
    main()
