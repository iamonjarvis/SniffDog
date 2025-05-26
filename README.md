# 🐶 SniffDog

**SniffDog** is a Python/Tkinter-powered GUI packet sniffer that makes network monitoring simple, visual, and efficient. It features real-time packet capture with protocol-based color-coding, IP/port details, timestamps, and a clean dark-themed interface.

---

## ✨ Features

- 🕵️‍♂️ Live packet capture with Start / Pause / Resume / Stop
- 🎨 Color-coded protocol rows (TCP, UDP, ICMP, Others)
- 🧠 Displays timestamp, source/destination IPs & ports, and protocol type
- 🌐 Shows host IP address
- 🖤 Modern dark-themed scrollable table view
- 🐧 Cross-platform support (Tested on Linux, .deb & Snap available)

---

## 📦 Installation

### ✅ Snap Store (Recommended – 1-Click Install)
```bash
sudo snap install sniffdog
```

> You must use `--devmode` if you're testing locally:
```bash
sudo snap install sniffdog --devmode
```

Snap Store: https://snapcraft.io/sniffdog

---

### ✅ .deb Package
Download `.deb` from [Releases](https://github.com/iamonjarvis/SniffDog/releases)

Install:
```bash
sudo dpkg -i sniffdog_1.0_amd64.deb
```

---

### ✅ Manual (from source)

1. **Clone the repo**:
```bash
git clone https://github.com/iamonjarvis/SniffDog.git
cd SniffDog
```

2. **Create virtual environment**:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

3. **Install dependencies (if not already)**:
```bash
sudo apt install python3-tk
```

---

## ▶️ Usage

1. Run SniffDog with:
```bash
python3 main.py
```

2. Or use your `.deb` or `sniffdog` command from terminal (if installed via Snap)

---

## 📸 Preview

![SniffDog Screenshot](https://github.com/user-attachments/assets/10988bb3-2e45-4968-ba2e-57e738a357c1)

---

## 📄 License

MIT © Sahil Patra 2025

---

## 🔗 Links

- 🔗 [Snap Store](https://snapcraft.io/sniffdog)
- 💻 [GitHub Repository](https://github.com/iamonjarvis/SniffDog)
- 🌐 [Portfolio](https://sahilpatra.site)

---

> Built with 🐍 Python + 🖼️ Tkinter + 📡 Scapy  
> Made with ❤️ by Sahil Patra
