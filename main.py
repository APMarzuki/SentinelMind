import sys
from modules.database_mgr import DatabaseManager
from modules.api_client import SentinelAPI
from core.eye import SentinelEye

def show_menu():
    print("\n" + "="*50)
    print("🛡️  SENTINELMIND COMMAND CENTER  🛡️")
    print("="*50)
    print("1. [Sync] Fetch Latest Threat Intel (OTX + AbuseIPDB)")
    print("2. [Monitor] Start Live Network Guardian (The Eye)")
    print("3. [Database] Check Current Threat Count")
    print("4. [Exit] Shutdown System")
    print("="*50)

def main():
    db = DatabaseManager()
    api = SentinelAPI()
    eye = SentinelEye()

    while True:
        show_menu()
        choice = input("\n[>] Select Option: ")

        if choice == '1':
            print("\n[*] Starting Enriched Sync...")
            # We use the logic we tested earlier
            indicators = api.get_otx_pulses(limit=3)
            if indicators:
                for item in indicators:
                    # Quick enrichment if it's an IP
                    if item['type'] == 'ipv4':
                        abuse = api.check_abuseipdb(item['value'])
                        if abuse:
                            item['score'] = abuse.get('abuseConfidenceScore', 75)
                    db.add_indicator(item['value'], item['type'], item['source'], item['score'])
                print(f"[+] Sync Complete. Brain updated.")
            else:
                print("[-] No new data found.")


        elif choice == '2':

            print("\n[*] Initializing The Eye...")

            # REPLACE 'Wi-Fi' with the name you found in Step 2

            # If you are unsure, leave it as None first

            target_iface = input("[?] Enter interface name (leave blank for default): ").strip()

            iface = target_iface if target_iface else None

            try:

                eye.start_sniffing(interface=iface)

            except KeyboardInterrupt:

                print("\n[!] Monitoring Stopped.")

        elif choice == '3':
            # Quick database check
            import sqlite3
            conn = sqlite3.connect('data/threat_intel.db')
            count = conn.execute('SELECT COUNT(*) FROM indicators').fetchone()[0]
            print(f"\n[i] The Brain currently knows {count} unique threats.")
            conn.close()

        elif choice == '4':
            print("[*] SentinelMind shutting down. Stay safe.")
            sys.exit()

        else:
            print("[!] Invalid selection.")

if __name__ == "__main__":
    main()