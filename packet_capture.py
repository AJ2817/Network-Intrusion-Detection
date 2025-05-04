
from scapy.all import sniff, IP, TCP, wrpcap
from collections import defaultdict
import threading
import queue
import time
import os

class PacketCapture:
    def __init__(self, interface="eth0", output_file="captured.pcap"):
        self.interface = interface
        self.packet_queue = queue.Queue()
        self.stop_capture = threading.Event()
        self.output_file = output_file
        self.captured_packets = []

    def packet_callback(self, packet):
        if IP in packet and TCP in packet:
            self.packet_queue.put(packet)
            self.captured_packets.append(packet)

    def start_capture(self, capture_duration=30):
        def capture_thread():
            print(f"[+] Starting packet capture on interface: {self.interface}")
            while not self.stop_capture.is_set():
                sniff(
                    iface=self.interface,
                    prn=self.packet_callback,
                    store=0,
                    timeout=5
                )

        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.start()

        # Automatically stop after capture_duration
        time.sleep(capture_duration)
        self.stop()

    def stop(self):
        print("[+] Stopping packet capture...")
        self.stop_capture.set()
        self.capture_thread.join()

        # Save to PCAP
        if self.captured_packets:
            wrpcap(self.output_file, self.captured_packets)
            print(f"[+] Saved {len(self.captured_packets)} packets to {self.output_file}")
        else:
            print("[!] No packets captured.")


class TrafficAnalyzer:
    def __init__(self):
        self.connections = defaultdict(list)
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None
        })

    def analyze_packet(self, packet):
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport

            flow_key = (ip_src, ip_dst, port_src, port_dst)

            stats = self.flow_stats[flow_key]
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            current_time = packet.time

            if not stats['start_time']:
                stats['start_time'] = current_time
            stats['last_time'] = current_time

            return self.extract_features(packet, stats)

    def extract_features(self, packet, stats):
        duration = stats['last_time'] - stats['start_time']
        if duration == 0:
            duration = 1e-6

        return {
            'packet_size': len(packet),
            'flow_duration': duration,
            'packet_rate': stats['packet_count'] / duration,
            'byte_rate': stats['byte_count'] / duration,
            'tcp_flags': packet[TCP].flags,
            'window_size': packet[TCP].window
        }


if __name__ == "__main__":
    INTERFACE = "eth0"  # Replace with your VM's interface
    CAPTURE_TIME = 30
    PCAP_FILE = "captured.pcap"

    capture = PacketCapture(interface=INTERFACE, output_file=PCAP_FILE)
    capture.start_capture(capture_duration=CAPTURE_TIME)

    analyzer = TrafficAnalyzer()
    while not capture.packet_queue.empty():
        pkt = capture.packet_queue.get()
        features = analyzer.analyze_packet(pkt)
        if features:
            print(features)

    print("[+] Done.")
