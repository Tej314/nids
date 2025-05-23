# nids.py - Step 3: Detect SYN floods and port scans

from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time

# Track SYN packets: { src_ip: [(port, timestamp), ...] }
syn_records = defaultdict(list)

# Thresholds
FLOOD_THRESHOLD = 100    # SYNs in 10 seconds
SCAN_THRESHOLD = 20      # Unique ports in 10 seconds
WINDOW_SECONDS = 10

def log_suspicious_activity(message):
    print(f"[ALERT] {message}")
    with open("suspicious_activity.txt", "a") as f:
        f.write(f"[{time.ctime()}] {message}\n")

def detect_syn(packet):
    print("[DEBUG] Packet seen")
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip = packet[IP].src
        port = packet[TCP].dport
        flags = packet[TCP].flags

        if flags == 'S':  # SYN
            print(f"[DEBUG] SYN from {ip} to port {port}")  # This should show during hping3 flood
            now = time.time()
            syn_packets[ip].append(now)

            # Remove timestamps older than 10s
            syn_packets[ip] = [t for t in syn_packets[ip] if now - t <= 10]

            # Detection thresholds
            if len(syn_packets[ip]) > 100:
                alert = f"[{time.ctime(now)}] Possible SYN flood from {ip} ({len(syn_packets[ip])} SYNs in 10s)"
                print(alert)
                with open("suspicious_activity.txt", "a") as f:
                    f.write(alert + "\n")

            # Detect port scan
            unique_ports = set(p for p, _ in syn_records[ip])
            if len(unique_ports) > SCAN_THRESHOLD:
                log_suspicious_activity(f"Possible port scan from {ip} ({len(unique_ports)} ports in {WINDOW_SECONDS}s)")

# Sniff only TCP packets
sniff(filter="tcp", iface="lo", prn=detect_syn, store=False)
