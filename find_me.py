from scapy.all import conf, get_if_addr

print("\n--- Available Interfaces ---")
print(conf.ifaces) # This lists all interfaces with their Names and IPs

print(f"\n[*] Your current default interface is: {conf.iface.name}")
print(f"[*] Its IP address is: {get_if_addr(conf.iface)}")