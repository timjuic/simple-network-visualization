# traffic_capture.py
from scapy.all import sniff
from collections import defaultdict
import time
import json
from threading import Thread
import queue

class NetworkMonitor:
    def __init__(self):
        # Queue to handle packet processing asynchronously
        self.packet_queue = queue.Queue()

        # Statistics storage using defaultdict
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

        # Extract protocol information
        protocol = packet.name if hasattr(packet, 'name') else 'unknown'

        # Extract IP information if available
        src_ip = packet.getlayer('IP').src if packet.haslayer('IP') else None
        dst_ip = packet.getlayer('IP').dst if packet.haslayer('IP') else None

        # Put packet info in queue for processing
        self.packet_queue.put({
            'timestamp': timestamp,
            'size': size,
            'protocol': protocol,
            'src_ip': src_ip,
            'dst_ip': dst_ip
        })

    def process_packets(self):
        """Process packets from the queue and update statistics"""
        while True:
            try:
                packet_info = self.packet_queue.get(timeout=1)

                # Group statistics by minute
                current_minute = int(packet_info['timestamp'] // 60) * 60

                # Update basic statistics
                self.stats[current_minute]['packets'] += 1
                self.stats[current_minute]['bytes'] += packet_info['size']
                self.stats[current_minute]['protocols'][packet_info['protocol']] += 1

                # Update IP statistics if available
                if packet_info['src_ip']:
                    self.stats[current_minute]['ip_sources'][packet_info['src_ip']] += 1
                if packet_info['dst_ip']:
                    self.stats[current_minute]['ip_destinations'][packet_info['dst_ip']] += 1

            except queue.Empty:
                continue

    def start_capture(self, interface="en0"):  # Use "en0" for Mac, "eth0" for Linux
        """Start packet capture on specified interface"""
        # Start packet processing thread
        process_thread = Thread(target=self.process_packets, daemon=True)
        process_thread.start()

        print(f"Starting capture on interface {interface}")
        # Start packet capture
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