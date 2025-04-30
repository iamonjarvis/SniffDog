# packet_data.py
from scapy.layers.inet import IP, TCP, UDP, ICMP
import time
import socket

def format_packet_data(packet):
    data = {}
    ts = getattr(packet, 'time', time.time())
    data["Timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        try:
            src_name = socket.gethostbyaddr(src_ip)[0]
        except socket.herror:
            src_name = ''
        try:
            dst_name = socket.gethostbyaddr(dst_ip)[0]
        except socket.herror:
            dst_name = ''
        data["Source"] = f"{src_ip} ({src_name})" if src_name else src_ip
        data["Destination"] = f"{dst_ip} ({dst_name})" if dst_name else dst_ip

        proto = packet[IP].proto
        data["Protocol"] = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, str(proto))

        if TCP in packet:
            data["Source Port"] = packet[TCP].sport
            data["Destination Port"] = packet[TCP].dport
        elif UDP in packet:
            data["Source Port"] = packet[UDP].sport
            data["Destination Port"] = packet[UDP].dport
        else:
            data["Source Port"] = ''
            data["Destination Port"] = ''

        data["Header"] = packet.summary()
    else:
        data["Source"] = ''
        data["Destination"] = ''
        data["Protocol"] = packet.name if hasattr(packet, 'name') else ''
        data["Source Port"] = ''
        data["Destination Port"] = ''
        data["Header"] = packet.summary() if hasattr(packet, 'summary') else ''

    return data