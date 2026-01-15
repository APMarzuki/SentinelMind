from scapy.all import sniff, IP, TCP, UDP, ICMP
from modules.database_mgr import DatabaseManager
import datetime
import os


class SentinelEye:
    def __init__(self):
        self.db = DatabaseManager()
        self.log_file = "data/alerts.log"
        # Ensure data folder exists for logs
        os.makedirs("data", exist_ok=True)
        print("[*] SentinelEye: Professional Lens Active. Logging to data/alerts.log")

    def log_alert(self, threat_data, dst_ip, proto, port):
        """Saves the alert details to a text file for later review."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = (
            f"[{timestamp}] ALERT: {dst_ip} | Proto: {proto} | Port: {port} | "
            f"Source: {threat_data['source']} | Score: {threat_data['score']}%\n"
        )
        with open(self.log_file, "a") as f:
            f.write(log_entry)

    def process_packet(self, packet):
        """Analyzes packets for known threats with protocol and port details."""
        if packet.haslayer(IP):
            dst_ip = packet[IP].dst
            proto = "OTHER"
            port = "N/A"

            # Identify Protocol and Port
            if packet.haslayer(TCP):
                proto = "TCP"
                port = packet[TCP].dport
            elif packet.haslayer(UDP):
                proto = "UDP"
                port = packet[UDP].dport
            elif packet.haslayer(ICMP):
                proto = "ICMP"

            # Check the Brain (Database)
            threat = self.db.get_indicator(dst_ip)

            if threat:
                # 1. Print to Terminal
                print(f"\n[!!!] ALERT: Known Threat Detected!")
                print(f"      Target: {dst_ip} ({proto}:{port})")
                print(f"      Source: {threat['source']} | Risk: {threat['score']}%")

                # 2. Save to Log File
                self.log_alert(threat, dst_ip, proto, port)

    def start_sniffing(self, interface=None):
        """Starts the live capture loop."""
        print(f"[*] Sniffing started on {interface if interface else 'default interface'}...")
        sniff(iface=interface, prn=self.process_packet, store=0)


if __name__ == "__main__":
    eye = SentinelEye()
    eye.start_sniffing()