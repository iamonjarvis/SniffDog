from scapy.all import sniff, IP
import threading
from packet_data import format_packet_data
import csv

stop_sniffing_flag = False
paused = False
sniff_thread = None
packet_buffer = []


def packet_callback(packet, callback):
    if not paused and IP in packet:
        info = format_packet_data(packet)
        packet_buffer.append(info)
        callback(info)


def start_sniffing(callback):
    global stop_sniffing_flag, sniff_thread, paused, packet_buffer
    stop_sniffing_flag = False
    paused = False
    packet_buffer = []

    def sniffing():
        sniff(prn=lambda pkt: packet_callback(pkt, callback),
              stop_filter=lambda x: stop_sniffing_flag,
              store=0)

    sniff_thread = threading.Thread(target=sniffing, daemon=True)
    sniff_thread.start()


def stop_sniffing():
    global stop_sniffing_flag
    stop_sniffing_flag = True


def toggle_pause():
    global paused
    paused = not paused
    return paused


def get_all_packets():
    return packet_buffer.copy()


# ✅ New: CSV Export Function
def export_to_csv(file_path="packets.csv"):
    if not packet_buffer:
        return

    headers = ["Timestamp", "Protocol", "Source", "Source Port", "Destination", "Destination Port", "Header"]
    with open(file_path, "w", newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for pkt in packet_buffer:
            writer.writerow({
                "Timestamp": pkt.get("Timestamp", ""),
                "Protocol": pkt.get("Protocol", ""),
                "Source": pkt.get("Source", ""),
                "Source Port": pkt.get("Source Port", ""),
                "Destination": pkt.get("Destination", ""),
                "Destination Port": pkt.get("Destination Port", ""),
                "Header": pkt.get("Header", "")
            })
