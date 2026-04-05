from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        timestamp = datetime.now().strftime('%H:%M:%S')

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags
            print(f"[{timestamp}] TCP {src_ip}:{src_port} -> {dst_ip}:{dst_port} flags = {flags}")

        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"[{timestamp}] UDP {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

        else:
            print(f"[{timestamp}] IP {src_ip} -> {dst_ip} protocol = {protocol}")

def start_monitor(interface = None):

    sniff(
        iface =  interface,
        prn = packet_callback,
        store = False
    )

if __name__ == "__main__":
    start_monitor()