
from scapy.all import sniff, IP, TCP
from collections import defaultdict
from datetime import datetime

attempts = defaultdict(int)

def detect_attack(packet):
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        # Check for a new TCP connection attempt
        if packet[TCP].flags == "S":
            key = (src_ip, dst_port)
            attempts[key] += 1

            if attempts[key] >= 10:
                message = (
                    f"ALERT: Repeated attempts from {src_ip} "
                    f"to port {dst_port}"
                )
                print(datetime.now(), message)

                with open("alerts.log", "a") as file:
                    file.write(f"{datetime.now()} {message}\n")

print("NIDS started. Press Ctrl+C to stop.")

try:
    sniff(filter="tcp", prn=detect_attack, store=False)
except KeyboardInterrupt:
    print("\nNIDS stopped.")
