"""Main module for the network monitor. Captures packets and passes them to the flow manager, 
which tracks active flows and extracts features when flows are completed or expired."""

from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
from flow import FlowManager
from features import extract_features
from predict import Predictor
from alerts import AlertManager
import threading 
import time
import argparse

#Init managers
flow_manager = FlowManager()
predictor = Predictor()
alert_manager = AlertManager()

def packet_callback(packet):
    
    """Called for each packet captured by scapy.
      Extracts flow info and passes it to the flow manager."""

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        size = len(packet)

        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = packet[TCP].flags

            #Add packet to the flow manager and check if the flow is completed (FIN/RST)
            completed = flow_manager.add_packet(
                src_ip, dst_ip, src_port, dst_port, protocol, size, flags
            )

            #If the flow is completed, extract features
            if completed:
                features = extract_features(completed, dst_port)

                start = time.time()
                label, confidence = predictor.predict(features)
                elapsed = (time.time() - start) * 1000
                print(f"Prediction time: {elapsed:.2f} ms")

                if predictor.is_attack(label):
                    print(f"[ALERT] Attack detected: {label} with {confidence:.2f}% confidence")
                    print(f"Flow: {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Protocol: {'TCP'} | Size: {size} bytes")

                    alert_manager.send_alert(
                        label, confidence, src_ip, dst_ip, src_port, dst_port, 'TCP'
                    )
                else:
                    print(f"[OK] Benign flow: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
    

        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            
            #UDP has no FIN/RST, so flows are completed based on timeout.
            flow_manager.add_packet(
                src_ip, dst_ip, src_port, dst_port, protocol, size
            )

def expire_flows_periodically():

    """Runs in a separate thread to periodically check for flows inactive outside the timeout threshold.
      When expired flows are found, features are extracted and printed."""
    
    while True:
        time.sleep(10)
        expired = flow_manager.expire_flows()
        for flow in expired:
            if flow.packets:
                features = extract_features(flow, flow.dst_port)
                label, confidence = predictor.predict(features)
                proto = 'UDP' if flow.protocol == 17 else 'TCP'

                if predictor.is_attack(label):
                    print(f"[ALERT] Attack detected: {label} with {confidence:.2f}% confidence")
                    print(f"Flow: {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} | Protocol: {proto} | Size: {flow.total_bytes} bytes")

                    alert_manager.send_alert(
                        label, confidence, flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, proto
                    )
                else:
                    print(f"[OK] Benign flow: {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port}")


def start_monitor(interface = None):

    """Starts the network monitor by initializing the flow manager, starting the expiry thread, and beginning packet capture on the default
    interface if none is specified."""

    print("Starting network monitor...")

    expiry_thread = threading.Thread(
        target = expire_flows_periodically,
        daemon = True
    )
    expiry_thread.start()

    #Start sniffing packets. prn calls packet_callback for each captured packet.
    sniff(
        iface =  interface,
        prn = packet_callback,
        store = False
    )

#
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--iface', type = str, default = None)
    args = parser.parse_args()
    start_monitor(interface = args.iface)