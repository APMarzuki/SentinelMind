import os
import requests
from OTXv2 import OTXv2
from dotenv import load_dotenv

# Load all secrets from the root .env file at the module level
load_dotenv()


class SentinelAPI:
    def __init__(self):
        # 1. API Credentials (Mapped to your sample.env)
        self.otx_key = os.getenv("OTX_API_KEY")
        self.vt_key = os.getenv("VT_API_KEY")
        self.abuse_key = os.getenv("ABUSEIPDB_API_KEY")
        self.urlscan_key = os.getenv("URLSCAN_API_KEY")
        self.shodan_key = os.getenv("SHODAN_API_KEY")
        self.metadefender_key = os.getenv("METADEFENDER_API_KEY")
        self.hybrid_key = os.getenv("HYBRID_ANALYSIS_API_KEY")
        self.st_key = os.getenv("SECURITYTRAILS_API_KEY")

        # Censys Credentials
        self.censys_id = os.getenv("CENSYS_ID")
        self.censys_secret = os.getenv("CENSYS_SECRET")
        self.censys_token = os.getenv("CENSYS_API_TOKEN")

        # 2. SDK Initializations
        self.otx = OTXv2(self.otx_key) if self.otx_key else None

        # 3. Fail-Safe Verification
        self._validate_keys()

    def _validate_keys(self):
        """Internal check to warn the user if core keys are missing."""
        core_keys = {
            "OTX": self.otx_key,
            "VirusTotal": self.vt_key,
            "AbuseIPDB": self.abuse_key
        }
        missing = [name for name, key in core_keys.items() if not key]
        if missing:
            print(f"\n[!] WARNING: Missing keys for: {', '.join(missing)}")
            print("[i] Ensure your '.env' file exists and contains these variables.")

    # --- [ THE BRAIN: REPUTATION & THREAT FEEDS ] ---

    def get_otx_pulses(self, limit=3):
        """Fetches recent malware pulses and extracts actionable indicators."""
        if not self.otx:
            return []
        try:
            print(f"[*] Searching OTX for {limit} malware pulses...")
            # SDK search_pulses often defaults to 25; we slice based on limit
            pulses = self.otx.search_pulses('malware')
            results = pulses.get('results', []) if isinstance(pulses, dict) else pulses

            extracted = []
            for pulse in results[:limit]:
                p_id = pulse.get('id')
                indicators = self.otx.get_pulse_indicators(p_id)
                for ind in indicators:
                    if ind['type'] in ['IPv4', 'domain']:
                        extracted.append({
                            'value': ind['indicator'],
                            'type': ind['type'].lower(),
                            'source': f"OTX_{p_id}",
                            'score': 75
                        })
            return extracted
        except Exception as e:
            print(f"[-] OTX API Error: {e}")
            return []

    def check_abuseipdb(self, ip):
        """Checks IP reputation score (0-100)."""
        if not self.abuse_key: return None
        url = 'https://api.abuseipdb.com/api/v2/check'
        headers = {'Accept': 'application/json', 'Key': self.abuse_key}
        params = {'ipAddress': ip, 'maxAgeInDays': '90'}
        try:
            res = requests.get(url, headers=headers, params=params, timeout=5)
            return res.json().get('data') if res.status_code == 200 else None
        except Exception:
            return None

    def check_virustotal(self, resource):
        """Checks VirusTotal v3 for IP/Domain."""
        if not self.vt_key: return None
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{resource}"
        headers = {"x-apikey": self.vt_key}
        try:
            res = requests.get(url, headers=headers, timeout=10)
            if res.status_code == 200:
                stats = res.json()['data']['attributes']['last_analysis_stats']
                return {"malicious": stats['malicious'], "suspicious": stats['suspicious']}
        except Exception:
            return None

    # --- [ THE EYE: INFRASTRUCTURE & VISUALS ] ---

    def check_censys(self, ip):
        """Fetches host details. Uses v3 Platform API (Bearer) or v2 Search (Basic Auth)."""
        auth = None
        headers = {"Accept": "application/json"}

        if self.censys_token:
            url = f"https://api.platform.censys.io/v3/hosts/{ip}"
            headers["Authorization"] = f"Bearer {self.censys_token}"
        elif self.censys_id and self.censys_secret:
            url = f"https://search.censys.io/api/v2/hosts/{ip}"
            auth = (self.censys_id, self.censys_secret)
        else:
            return None

        try:
            res = requests.get(url, headers=headers, auth=auth, timeout=10)
            return res.json() if res.status_code == 200 else None
        except Exception:
            return None

    def check_shodan(self, ip):
        if not self.shodan_key: return None
        url = f"https://api.shodan.io/shodan/host/{ip}?key={self.shodan_key}"
        try:
            res = requests.get(url, timeout=5)
            return res.json() if res.status_code == 200 else None
        except Exception:
            return None

    def check_securitytrails(self, domain):
        """Authentication requires 'APIKEY' header."""
        if not self.st_key: return None
        url = f"https://api.securitytrails.com/v1/domain/{domain}"
        headers = {"APIKEY": self.st_key}
        try:
            res = requests.get(url, headers=headers, timeout=5)
            return res.json() if res.status_code == 200 else None
        except Exception:
            return None

    # --- [ MALWARE ANALYSIS ] ---

    def check_metadefender(self, file_hash):
        if not self.metadefender_key: return None
        headers = {"apikey": self.metadefender_key}
        url = f"https://api.metadefender.com/v4/hash/{file_hash}"
        try:
            res = requests.get(url, headers=headers, timeout=5)
            return res.json() if res.status_code == 200 else None
        except Exception:
            return None

    def check_hybrid_analysis(self, file_hash):
        if not self.hybrid_key: return None
        headers = {"api-key": self.hybrid_key, "user-agent": "SentinelMind"}
        url = f"https://www.hybrid-analysis.com/api/v2/search/hash"
        data = {'hash': file_hash}
        try:
            res = requests.post(url, headers=headers, data=data, timeout=10)
            return res.json() if res.status_code == 200 else None
        except Exception:
            return None