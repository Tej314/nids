from scapy.all import sniff, IP, TCP
from collections import defaultdict
import time

syn_records = defaultdict(list)
port_records = defaultdict(list)

FLOOD_THRESHOLD = 100    
SCAN_THRESHOLD = 20      
WINDOW_SECONDS = 10

def log_suspicious_activity(message):
    print(f"[ALERT] {message}")
    with open("suspicious_activity.txt", "a") as f:
        f.write(f"[{time.ctime()}] {message}\n")

def detect_syn(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip = packet[IP].src
        port = packet[TCP].dport
        flags = packet[TCP].flags

        if flags == 'S':  
            now = time.time()
            syn_records[ip].append(now)
            syn_records[ip] = [t for t in syn_records[ip] if now - t <= WINDOW_SECONDS]

            if len(syn_records[ip]) > FLOOD_THRESHOLD:
                log_suspicious_activity(f"Possible SYN flood from {ip} ({len(syn_records[ip])} SYNs in {WINDOW_SECONDS}s)")

            port_records[ip].append((port, now))
            port_records[ip] = [(p, t) for (p, t) in port_records[ip] if now - t <= WINDOW_SECONDS]

            unique_ports = set(p for p, _ in port_records[ip])
            if len(unique_ports) > SCAN_THRESHOLD:
                log_suspicious_activity(f"Possible port scan from {ip} ({len(unique_ports)} ports in {WINDOW_SECONDS}s)")

sniff(filter="tcp", iface="lo", prn=detect_syn, store=False)
