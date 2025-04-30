# SniffDog

**SniffDog** is a Python/Tkinter packet sniffer with a live GUI that color-codes protocols, displays timestamps, ports, and headers, making network monitoring simple and visual.

## Features

- Live packet capture with start/stop controls
- Color-coded protocols (TCP, UDP, ICMP, others)
- Displays timestamp, source/destination IP and ports, header summary
- Interface selection and basic filter input
- Dark-themed, scrollable table view

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-username/SniffDog.git
   cd SniffDog
   ```

2. **Set up virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```

3. **Install Tkinter** (if not already):
   ```bash
   sudo apt install python3-tk
   ```

## Usage

1. **Run with elevated privileges**:
   ```bash
   chmod +x run_sniffer.sh
   ./run_sniffer.sh
   ```
2. **Click** **Start Sniffing** to begin
3. **Click** **Stop Sniffing** to end


## License

MIT © Sahil Patra 2025

