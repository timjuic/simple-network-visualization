
from scapy.all import sniff
from collections import defaultdict
import time
import json
from threading import Thread
import queue

class NetworkMonitor:
    def __init__(self):
        self.packet_queue = queue.Queue()

        self.stats = defaultdict(lambda: {
            'packets': 0,
            'bytes': 0,
            'protocols': defaultdict(int),
            'ip_sources': defaultdict(int),
            'ip_destinations': defaultdict(int)
        })

    def packet_callback(self, packet):
        """Callback function that processes each captured packet"""
        timestamp = time.time()
        size = len(packet)

        # Ispravno određivanje protokola
        if packet.haslayer('TCP'):
            protocol = 'TCP'
        elif packet.haslayer('UDP'):
            protocol = 'UDP'
        elif packet.haslayer('ICMP'):
            protocol = 'ICMP'
        elif packet.haslayer('DNS'):
            protocol = 'DNS'
        else:
            protocol = 'Other'

        # Dohvaćanje izvorišne i odredišne IP adrese
        src_ip = packet.getlayer('IP').src if packet.haslayer('IP') else None
        dst_ip = packet.getlayer('IP').dst if packet.haslayer('IP') else None

        # Spremanje informacija o paketu u queue za obradu
        self.packet_queue.put({
            'timestamp': timestamp,
            'size': size,
            'protocol': protocol,
            'src_ip': src_ip,
            'dst_ip': dst_ip
        })

    def process_packets(self):
        while True:
            try:
                packet_info = self.packet_queue.get(timeout=1)

                current_minute = int(packet_info['timestamp'] // 60) * 60

                self.stats[current_minute]['packets'] += 1
                self.stats[current_minute]['bytes'] += packet_info['size']
                self.stats[current_minute]['protocols'][packet_info['protocol']] += 1

                if packet_info['src_ip']:
                    self.stats[current_minute]['ip_sources'][packet_info['src_ip']] += 1
                if packet_info['dst_ip']:
                    self.stats[current_minute]['ip_destinations'][packet_info['dst_ip']] += 1

            except queue.Empty:
                continue

    def start_capture(self, interface="en0"):
        """Start packet capture on specified interface"""
        process_thread = Thread(target=self.process_packets, daemon=True)
        process_thread.start()

        print(f"Starting capture on interface {interface}")
        sniff(iface=interface, prn=self.packet_callback, store=0)

    def get_statistics(self, minutes=5):
        """Get statistics for the last N minutes"""
        current_time = int(time.time())
        start_time = current_time - (minutes * 60)

        return {
            timestamp: stats
            for timestamp, stats in self.stats.items()
            if timestamp >= start_time
        }