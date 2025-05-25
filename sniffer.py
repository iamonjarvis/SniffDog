# sniffer.py
from scapy.all import sniff, IP
import threading

class Sniffer:
    def __init__(self):
        self.running = False
        self.paused = False
        self.thread = None
        self.callback = None

    def _sniff(self):
        sniff(prn=self._process_packet, stop_filter=lambda x: not self.running, store=False)

    def _process_packet(self, packet):
        if self.paused or not self.callback:
            return
        if IP in packet:
            self.callback(packet)

    def start(self, callback):
        self.callback = callback
        self.running = True
        self.paused = False
        self.thread = threading.Thread(target=self._sniff, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False

    def pause(self):
        self.paused = True

    def resume(self):
        self.paused = False
