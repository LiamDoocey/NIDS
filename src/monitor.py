"""Main module for the network monitor. Captures packets and passes them to the flow manager, 
which tracks active flows and extracts features when flows are completed or expired."""

from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
from flow import FlowManager
from features import extract_features
from predict import Predictor
from alerts import AlertManager
from threat_intel import ThreatIntel
from dashboard import add_traffic_event, start_dashboard
import threading 
import time
import argparse

from dotenv import load_dotenv
load_dotenv()

#Init managers
flow_manager = FlowManager()
predictor = Predictor()
alert_manager = AlertManager()
threat_intel = ThreatIntel()


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

                #Layer 1: Check threat intelligence before ML prediction for faster detection of known threats and to provide additional context in alerts.
                intel = threat_intel.check_flow(src_ip, dst_ip)
                if intel['is_threat']:
                    print(f"[ALERT] Threat detected in flow: {src_ip} -> {dst_ip}")
                    print(f"Source IP: {src_ip} | Destination IP: {dst_ip} | Source Port: {src_port} | Destination Port: {dst_port} | Protocol: TCP | Size: {size} bytes")
                    print(f"Threat Intel - Source IP: {intel['src_ip_info']} | Destination IP: {intel['dst_ip_info']}")

                    add_traffic_event('THREAT_INTEL_MATCH', 'THREAT_INTEL_MATCH',
                        src_ip, dst_ip, src_port, dst_port, 'TCP',
                        intel['src_ip_info']['abuse_score'] if intel['src_ip_info'] else intel['dst_ip_info']['abuse_score'])

                    alert_manager.send_alert(
                        label = 'THREAT_INTEL_MATCH',
                        confidence = intel['src_ip_info']['abuse_score'] if intel['src_ip_info'] else intel['dst_ip_info']['abuse_score'],
                        src_ip = src_ip,
                        dst_ip = dst_ip,
                        src_port = src_port,
                        dst_port = dst_port,
                        protocol = 'TCP'
                    )
                    return

                label, confidence = predictor.predict(features)
            
                #Layer 2: Use ML prediction to detect novel or unknown attacks based on flow features. 
                # This allows us to catch emerging threats that may not be in threat intelligence databases yet.
                if predictor.is_attack(label):
                    print(f"[ALERT] Attack detected: {label} with {confidence:.2f}% confidence")
                    print(f"Flow: {src_ip}:{src_port} -> {dst_ip}:{dst_port} | Protocol: {'TCP'} | Size: {size} bytes")

                    add_traffic_event('ALERT', label, src_ip, dst_ip, src_port, dst_port, 'TCP', confidence)

                    alert_manager.send_alert(
                        label, confidence, src_ip, dst_ip, src_port, dst_port, 'TCP'
                    )
                else:
                    print(f"[OK] Benign flow: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                    add_traffic_event('OK', 'BENIGN', src_ip, dst_ip, src_port, dst_port, 'TCP', confidence)
    

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
                proto = 'UDP' if flow.protocol == 17 else 'TCP'

                #Layer 1: Check threat intelligence before ML prediction for faster detection of known threats and to provide additional context in alerts.
                intel = threat_intel.check_flow(flow.src_ip, flow.dst_ip)
                if intel['is_threat']:
                    print(f"[ALERT] Threat detected in flow: {flow.src_ip} -> {flow.dst_ip}")
                    print(f"Source IP: {flow.src_ip} | Destination IP: {flow.dst_ip} | Source Port: {flow.src_port} | Destination Port: {flow.dst_port} | Protocol: {proto}")
                    print(f"Threat Intel - Source IP: {intel['src_ip_info']} | Destination IP: {intel['dst_ip_info']}")

                    add_traffic_event('THREAT_INTEL_MATCH', 'THREAT_INTEL_MATCH',
                        flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, 'TCP',
                        intel['src_ip_info']['abuse_score'] if intel['src_ip_info'] else intel['dst_ip_info']['abuse_score'])

                    alert_manager.send_alert(
                        label = 'THREAT_INTEL_MATCH',
                        confidence = intel['src_ip_info']['abuse_score'] if intel['src_ip_info'] else intel['dst_ip_info']['abuse_score'],
                        src_ip = flow.src_ip,
                        dst_ip = flow.dst_ip,
                        src_port = flow.src_port,
                        dst_port = flow.dst_port,
                        protocol = proto
                    )
                    continue

                #Layer 2: Use ML prediction to detect novel or unknown attacks based on flow features. 
                label, confidence = predictor.predict(features)
                if predictor.is_attack(label):
                    print(f"[ALERT] Attack detected: {label} with {confidence:.2f}% confidence")
                    print(f"Flow: {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port} | Protocol: {proto}")

                    add_traffic_event('ALERT', label, flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, 'TCP', confidence)

                    alert_manager.send_alert(
                        label, confidence, flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, proto
                    )
                else:
                    print(f"[OK] Benign flow: {flow.src_ip}:{flow.src_port} -> {flow.dst_ip}:{flow.dst_port}")
                    add_traffic_event('OK', 'BENIGN', flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port, 'TCP', confidence)


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

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--iface', type = str, default = None)
    args = parser.parse_args()

    dashboard_thread = threading.Thread(
        target = start_dashboard,
        daemon = True
    )
    dashboard_thread.start()

    start_monitor(interface = args.iface)