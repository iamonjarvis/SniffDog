# sniffer.py
from scapy.all import sniff, IP
import threading
from packet_data import format_packet_data

stop_sniffing_flag = False
sniff_thread = None

def packet_callback(packet, callback):
    if IP in packet:
        info = format_packet_data(packet)
        callback(info)  # Send data to GUI

def start_sniffing(callback):
    global stop_sniffing_flag, sniff_thread
    stop_sniffing_flag = False

    def sniffing():
        sniff(prn=lambda pkt: packet_callback(pkt, callback), stop_filter=lambda x: stop_sniffing_flag, store=0)

    sniff_thread = threading.Thread(target=sniffing, daemon=True)
    sniff_thread.start()

def stop_sniffing():
    global stop_sniffing_flag
    stop_sniffing_flag = True
