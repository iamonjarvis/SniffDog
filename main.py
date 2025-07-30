from gui import create_gui
from sniffer import start_sniffing, stop_sniffing, toggle_pause

if __name__ == "__main__":
    create_gui(start_sniffing, stop_sniffing, toggle_pause)
