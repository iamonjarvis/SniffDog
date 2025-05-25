# main.py
from gui import PacketSnifferGUI
from sniffer import Sniffer
import tkinter as tk

def create_gui(sniffer):
    root = tk.Tk()
    PacketSnifferGUI(root, sniffer)
    root.mainloop()

if __name__ == "__main__":
    sniffer = Sniffer()
    create_gui(sniffer)
