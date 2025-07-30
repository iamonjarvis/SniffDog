import tkinter as tk
from tkinter import ttk
from datetime import datetime
from tkinter import filedialog, messagebox
from sniffer import get_all_packets, export_to_csv
import socket


class PacketSnifferGUI:
    def __init__(self, root, start_callback, stop_callback, toggle_pause_callback):
        self.root = root
        self.start_callback = start_callback
        self.stop_callback = stop_callback
        self.toggle_pause_callback = toggle_pause_callback
        self.paused = False
        self.protocol_filter = "ALL"

        root.title("SniffDog - Network Packet Sniffer")
        root.geometry("1100x650")
        root.configure(bg="#121212")

        style = ttk.Style()
        style.theme_use("clam")

        style.configure("TButton",
                        font=("Segoe UI", 10),
                        padding=6,
                        relief="flat")
        style.map("TButton",
                  background=[("active", "#3c3f41")],
                  foreground=[("active", "white")])

        style.configure("Green.TButton", foreground="white", background="#28a745", font=("Segoe UI", 10, "bold"))
        style.configure("Red.TButton", foreground="white", background="#dc3545", font=("Segoe UI", 10, "bold"))
        style.configure("Yellow.TButton", foreground="black", background="#ffc107", font=("Segoe UI", 10, "bold"))

        style.configure("Treeview",
                        background="#1e1e1e",
                        foreground="white",
                        fieldbackground="#1e1e1e",
                        rowheight=28,
                        font=("Segoe UI", 9))
        style.map("Treeview",
                  background=[('selected', '#444444')],
                  foreground=[('selected', 'white')])

        # Host details (IP address)
        try:
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
        except Exception:
            hostname = "Unknown"
            ip_address = "Unavailable"

        host_frame = tk.Frame(root, bg="#121212")
        host_frame.pack(fill="x", pady=(8, 4))

        host_label = tk.Label(
            host_frame,
            text=f"🖥  Host: {hostname}    🌐 IP: {ip_address}",
            fg="lightgreen",
            bg="#121212",
            font=("Segoe UI", 11, "bold"),
            anchor="w"
        )
        host_label.pack(padx=15, anchor="w")

        control_frame = tk.Frame(root, bg="#121212")
        control_frame.pack(fill="x", pady=10, padx=15)

        self.start_button = ttk.Button(control_frame, text="▶ Start", style="Green.TButton", command=self.start)
        self.start_button.pack(side="left", padx=5)

        self.pause_button = ttk.Button(control_frame, text="⏸ Pause", style="Yellow.TButton", command=self.toggle_pause)
        self.pause_button.pack(side="left", padx=5)

        self.stop_button = ttk.Button(control_frame, text="⏹ Stop", style="Red.TButton", command=self.stop)
        self.stop_button.pack(side="left", padx=5)

        self.export_button = ttk.Button(control_frame, text="💾 Export CSV", style="Green.TButton",
                                        command=self.export_data)
        self.export_button.pack(side="left", padx=5)

        # Filter on the right
        filter_frame = tk.Frame(control_frame, bg="#121212")
        filter_frame.pack(side="right", padx=5)

        tk.Label(filter_frame, text="Filter Protocol:", bg="#121212", fg="white", font=("Segoe UI", 10, "bold")).pack(side="left")

        self.filter_var = tk.StringVar(value="ALL")
        filter_menu = ttk.OptionMenu(filter_frame, self.filter_var, "ALL", "ALL", "TCP", "UDP", "ICMP", command=self.apply_filter)
        filter_menu.pack(side="left", padx=6)

        # Treeview
        cols = ("Timestamp", "Protocol", "Source", "Src Port", "Destination", "Dst Port", "Header")
        self.tree = ttk.Treeview(root, columns=cols, show="headings")

        for col in cols:
            self.tree.heading(col, text=col)
            width = 320 if col == "Header" else 120
            self.tree.column(col, width=width, anchor="w")

        vsb = ttk.Scrollbar(root, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(root, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscroll=vsb.set, xscroll=hsb.set)

        vsb.pack(side="right", fill="y")
        hsb.pack(side="bottom", fill="x")
        self.tree.pack(expand=True, fill="both", padx=15, pady=10)

        # Footer
        self.footer = tk.Label(root, text="SniffDog © 2025  |  Created by Sahil Patra",
                               fg="#888", bg="#121212", font=("Segoe UI", 9))
        self.footer.pack(side="bottom", pady=8)

        # Tag-based coloring
        self.tree.tag_configure("TCP", background="#0d47a1", foreground="white")
        self.tree.tag_configure("UDP", background="#6a1b9a", foreground="white")
        self.tree.tag_configure("ICMP", background="#ff8c00", foreground="black")
        self.tree.tag_configure("OTHER", background="#424242", foreground="white")

    def start(self):
        self.start_callback(self.on_packet)

    def stop(self):
        self.stop_callback()

    def toggle_pause(self):
        self.paused = self.toggle_pause_callback()
        self.pause_button.config(text="▶ Resume" if self.paused else "⏸ Pause")

    def apply_filter(self, selected_protocol):
        self.protocol_filter = selected_protocol.upper()
        self.refresh_tree()

    def refresh_tree(self):
        self.tree.delete(*self.tree.get_children())
        for packet_info in get_all_packets():
            self.insert_packet(packet_info)

    def insert_packet(self, packet_info):
        protocol = packet_info.get("Protocol", "").upper()
        if self.protocol_filter != "ALL" and protocol != self.protocol_filter:
            return

        timestamp = packet_info.get("Timestamp", datetime.now().strftime("%H:%M:%S"))
        values = (
            timestamp,
            protocol,
            packet_info.get("Source", ""),
            packet_info.get("Source Port", ""),
            packet_info.get("Destination", ""),
            packet_info.get("Destination Port", ""),
            packet_info.get("Header", "")
        )
        tag = protocol if protocol in ["TCP", "UDP", "ICMP"] else "OTHER"
        self.tree.insert("", "end", values=values, tags=(tag,))

    def on_packet(self, packet_info):
        self.insert_packet(packet_info)

    def export_data(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                                 filetypes=[("CSV files", "*.csv")],
                                                 title="Save Packet Data")
        if file_path:
            try:
                export_to_csv(file_path)
                messagebox.showinfo("Export Successful", f"Packet data exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Export Failed", str(e))


def create_gui(start_callback, stop_callback, toggle_pause_callback):
    root = tk.Tk()
    PacketSnifferGUI(root, start_callback, stop_callback, toggle_pause_callback)
    root.mainloop()
