from modules.api_client import SentinelAPI
from modules.database_mgr import DatabaseManager


def test_system():
    print("🔬 --- Starting SentinelMind System Test --- 🔬")

    api = SentinelAPI()
    db = DatabaseManager()

    # 1. Test a known "Bad" IP (Google DNS 8.8.8.8 for connectivity test)
    test_ip = "8.8.8.8"
    print(f"\n[*] Testing IP Reputation for: {test_ip}")

    # Test AbuseIPDB
    abuse_data = api.check_abuseipdb(test_ip)
    if abuse_data:
        print(f"[+] AbuseIPDB: Success! (Score: {abuse_data.get('abuseConfidenceScore')})")
    else:
        print("[-] AbuseIPDB: No data returned (Check your key).")

    # Test VirusTotal
    vt_data = api.check_virustotal(test_ip)
    if vt_data:
        print(f"[+] VirusTotal: Success! (Malicious detections: {vt_data['malicious']})")
    else:
        print("[-] VirusTotal: No data returned.")

    # 2. Test Database Storage
    print("\n[*] Testing Local Database Storage...")
    db.add_indicator(test_ip, 'ipv4', 'Manual_Test', 0)

    # Simple check to see if the file exists and has size
    import os
    if os.path.exists("data/threat_intel.db"):
        size = os.path.getsize("data/threat_intel.db")
        print(f"[+] Database file found! ({size} bytes)")
    else:
        print("[-] Database file missing!")


if __name__ == "__main__":
    test_system()