from modules.database_mgr import DatabaseManager

def seed_manual_threat():
    db = DatabaseManager()
    # We are telling the Brain that 1.1.1.1 is a dangerous malware source
    print("[*] Seeding 1.1.1.1 into the database...")
    db.add_indicator(
        indicator="1.1.1.1",
        i_type="ipv4",
        source="Manual_Test_Seeding",
        score=100
    )
    print("[+] Success! 1.1.1.1 is now a 'Wanted' IP in your local database.")

if __name__ == "__main__":
    seed_manual_threat()