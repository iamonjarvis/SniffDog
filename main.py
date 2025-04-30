# main.py
from gui import create_gui
from sniffer import start_sniffing, stop_sniffing

if __name__ == "__main__":
    create_gui(start_sniffing, stop_sniffing)
