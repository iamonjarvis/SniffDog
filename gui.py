# gui.py
import tkinter as tk
from tkinter import ttk
from scapy.layers.inet import IP, TCP, UDP, ICMP
from datetime import datetime
from utils import get_local_ip

class PacketSnifferGUI:
    def __init__(self, root, sniffer):
        self.root = root
        self.sniffer = sniffer

        self.root.title("SniffDog - Packet Sniffer")
        self.root.geometry("1100x600")
        self.root.configure(bg="#1e1e1e")

        style = ttk.Style()
        style.theme_use("clam")

        # Button Styles
        style.configure("TButton", font=("Segoe UI", 10, "bold"))
        style.configure("Start.TButton", background="#28a745", foreground="white")
        style.configure("Stop.TButton", background="#dc3545", foreground="white")
        style.configure("Pause.TButton", background="#ffc107", foreground="black")
        style.configure("Resume.TButton", background="#007bff", foreground="white")

        # Treeview Style
        style.configure("Treeview", background="#2e2e2e", foreground="white", fieldbackground="#2e2e2e", rowheight=25)
        style.map("Treeview", background=[('selected', '#444444')], foreground=[('selected', 'white')])

        # Host IP Display
        ip_frame = tk.Frame(root, bg="#1e1e1e")
        ip_frame.pack(pady=5)
        host_ip = get_local_ip()
        self.ip_label = tk.Label(ip_frame, text=f"Host IP: {host_ip}", bg="#1e1e1e", fg="lightgreen", font=("Segoe UI", 10, "bold"))
        self.ip_label.pack()

        # Control Buttons
        control_frame = tk.Frame(root, bg="#1e1e1e")
        control_frame.pack(pady=10)

        self.start_btn = ttk.Button(control_frame, text="Start", style="Start.TButton", command=self.start_sniffing)
        self.pause_btn = ttk.Button(control_frame, text="Pause", style="Pause.TButton", command=self.pause_sniffing)
        self.resume_btn = ttk.Button(control_frame, text="Resume", style="Resume.TButton", command=self.resume_sniffing)
        self.stop_btn = ttk.Button(control_frame, text="Stop", style="Stop.TButton", command=self.stop_sniffing)

        self.start_btn.pack(side="left", padx=10)
        self.pause_btn.pack(side="left", padx=10)
        self.resume_btn.pack(side="left", padx=10)
        self.stop_btn.pack(side="left", padx=10)

        # Packet Table
        cols = ("Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Timestamp")
        self.tree = ttk.Treeview(root, columns=cols, show="headings")
        for col in cols:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150 if "Port" in col else 180, anchor="w")

        vsb = ttk.Scrollbar(root, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=vsb.set)
        vsb.pack(side="right", fill="y")
        self.tree.pack(expand=True, fill="both", padx=10)

        # Protocol row tags
        self.tree.tag_configure("TCP", background="#005f9e", foreground="white")
        self.tree.tag_configure("UDP", background="#800080", foreground="white")
        self.tree.tag_configure("ICMP", background="#ff8c00", foreground="black")
        self.tree.tag_configure("OTHER", background="#555555", foreground="white")

        # Footer
        self.footer = tk.Label(root, text="© Sahil Patra 2025 - SniffDog", bg="#1e1e1e", fg="gray", font=("Segoe UI", 9))
        self.footer.pack(side="bottom", pady=5)

    def start_sniffing(self):
        self.tree.delete(*self.tree.get_children())
        self.sniffer.start(self.on_packet)

    def pause_sniffing(self):
        self.sniffer.pause()

    def resume_sniffing(self):
        self.sniffer.resume()

    def stop_sniffing(self):
        self.sniffer.stop()

    def on_packet(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(packet[IP].proto, "OTHER")
            sport = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else ""
            dport = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else ""
            timestamp = datetime.now().strftime("%H:%M:%S")

            self.tree.insert("", "end", values=(src_ip, sport, dst_ip, dport, proto, timestamp), tags=(proto,))
