#ARP_Spoof_Detector

# 🛡️ ARP Spoof Detector

## 📌 Overview
**ARP Spoof Detector** is a Python-based **real-time ARP spoofing detection tool** that monitors network traffic to detect malicious activities.

🚨 **Key Features:**
- 🏴‍☠️ **Detects ARP spoofing attacks** in real time.
- 🔍 **Active MAC verification** to prevent false positives.
- ⏱️ **Monitors packet timing** to catch suspicious ARP replies.
- 📜 **Logs all detected attacks** for further analysis.
- 🍋 **ASCII Mango Art** for added aesthetics.

## 🖥️ Installation
### 📦 Prerequisites
Ensure you have **Python 3.x** installed and the required dependencies:
```bash
sudo apt update && sudo apt install python3-pip -y
pip3 install scapy prettytable
```

## 🚀 Usage
Run the script with root privileges:
```bash
sudo python3 ARP_Spoof_Detector.py
```

### 🎯 Expected Output
- The script starts sniffing ARP packets.
- Alerts are displayed when **ARP poisoning is detected**.
- A log file (`arp_spoof_log.txt`) is created with attack details.

### 📜 Example Alert
```
🚨 [ALERT] ARP Spoofing Detected! 🚨
Reason: MAC Address Mismatch
🔹 IP: 192.168.1.10
🔹 Fake MAC: aa:bb:cc:dd:ee:ff (Potential Attacker)
🔹 Real MAC: 11:22:33:44:55:66 (Expected Device)
Timestamp: 2025-03-06 18:30:45
```

## 🛠️ How It Works
1. **Passive Detection**: Sniffs incoming ARP packets and checks for IP-MAC inconsistencies.
2. **Active Validation**: Queries the real MAC address of devices to verify authenticity.
3. **Behavioral Analysis**: Detects suspicious timing patterns (e.g., too-fast ARP replies).
4. **Logging & Reporting**: Logs attack details for future forensic analysis.

## 🔥 Why Use This?
✔️ **Stronger than basic ARP sniffers** – Detects attacks with smarter logic.
✔️ **Real-time detection** – Stops ARP poisoning before major damage occurs.
✔️ **Hacker-proof defense** – Logs detailed attack traces for better security analysis.

## 🚨 Important Notes
- Requires **root privileges** to sniff network packets.
- Works best on **Linux** (Tested on Kali Linux & Ubuntu).
- Does not block attacks – it's a **detection tool**, not a firewall.

## 📜 License
This project is **open-source** under the MIT License.

## 🤝 Contributing
Pull requests and improvements are welcome!

## 📞 Contact
For issues or improvements, feel free to reach out.

---
💡 *"The packet lies, but the network remembers."* 🔥


