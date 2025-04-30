import tkinter as tk
from tkinter import ttk
from packet_data import format_packet_data
from datetime import datetime

class PacketSnifferGUI:
    def __init__(self, root, start_callback, stop_callback):
        self.root = root
        self.start_callback = start_callback
        self.stop_callback = stop_callback

        root.title("Packet Sniffer")
        root.geometry("1000x600")
        root.configure(bg="#1e1e1e")

        style = ttk.Style()
        style.theme_use("clam")

        # Button Styles
        style.configure("Green.TButton", foreground="white", background="#28a745", font=("Segoe UI", 10, "bold"))
        style.map("Green.TButton", background=[("active", "#218838")])

        style.configure("Red.TButton", foreground="white", background="#dc3545", font=("Segoe UI", 10, "bold"))
        style.map("Red.TButton", background=[("active", "#c82333")])

        # Treeview style for better contrast
        style.configure("Treeview", background="#2e2e2e", foreground="white", fieldbackground="#2e2e2e", rowheight=25)
        style.map("Treeview", background=[('selected', '#666666')], foreground=[('selected','white')])

        control_frame = tk.Frame(root, bg="#1e1e1e")
        control_frame.pack(fill="x", pady=10)

        self.start_button = ttk.Button(control_frame, text="Start Sniffing", style="Green.TButton", command=self.start)
        self.start_button.pack(side="left", padx=10)

        self.stop_button = ttk.Button(control_frame, text="Stop Sniffing", style="Red.TButton", command=self.stop)
        self.stop_button.pack(side="left", padx=10)

        # Treeview for packet display
        cols = ("Timestamp", "Protocol", "Source", "Src Port", "Destination", "Dst Port", "Header")
        self.tree = ttk.Treeview(root, columns=cols, show="headings")
        for col in cols:
            self.tree.heading(col, text=col)
            width = 300 if col == "Header" else 100
            self.tree.column(col, width=width, anchor="w")

        vsb = ttk.Scrollbar(root, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(root, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscroll=vsb.set, xscroll=hsb.set)

        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        self.tree.pack(expand=True, fill="both", padx=10, pady=5)

        # Footer
        self.footer = tk.Label(root, text="(c) Sahil Patra 2025", fg="gray", bg="#1e1e1e", font=("Segoe UI", 9))
        self.footer.pack(side="bottom", pady=5)

        # Configure color tags
        self.tree.tag_configure("TCP", background="#005f9e", foreground="white")  # dark blue
        self.tree.tag_configure("UDP", background="#800080", foreground="white")  # purple
        self.tree.tag_configure("ICMP", background="#ff8c00", foreground="black")  # orange
        self.tree.tag_configure("OTHER", background="#555555", foreground="white")  # gray

    def start(self):
        self.start_callback(self.on_packet)

    def stop(self):
        self.stop_callback()

    def on_packet(self, packet_info):
        timestamp = packet_info.get("Timestamp", datetime.now().strftime("%H:%M:%S"))
        values = (
            timestamp,
            packet_info.get("Protocol", ""),
            packet_info.get("Source", ""),
            packet_info.get("Source Port", ""),
            packet_info.get("Destination", ""),
            packet_info.get("Destination Port", ""),
            packet_info.get("Header", "")
        )
        proto = packet_info.get("Protocol", "OTHER").upper()
        self.tree.insert("", "end", values=values, tags=(proto,))


def create_gui(start_callback, stop_callback):
    root = tk.Tk()
    PacketSnifferGUI(root, start_callback, stop_callback)
    root.mainloop()
