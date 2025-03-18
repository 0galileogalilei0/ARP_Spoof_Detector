from scapy.all import ARP, sniff, srp, Ether
from prettytable import PrettyTable
import time
import os
import logging

# ✨ Cosmic Mango of Digital Wisdom ✨
mango_art = """
        .-"      "-.
       /            \\
      |   MANGO      |
      |  DETECTOR    |
       \\          /
        '-......-'
     A fruit of wisdom.
"""

# 🌌 Philosophical Thought: Every packet tells a story.
# Some packets whisper truth. Others scream deception.

# Configure Logging
logging.basicConfig(filename="arp_spoof_log.txt", level=logging.INFO, format="%(asctime)s - %(message)s")

# 🛡️ The Sacred Knowledge of MAC-IP Truths
network_state = {}

# Function to actively query an IP's real MAC address
def get_real_mac(ip):
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    ans, _ = srp(pkt, timeout=1, verbose=False)
    for sent, received in ans:
        return received.hwsrc  # The real MAC address
    return None

# 🚨 The Watcher: Analyzing Every ARP Packet
def analyze_arp_packet(pkt):
    if pkt.haslayer(ARP) and pkt.op == 2:  # ARP Reply (Someone saying "I am this IP")
        src_ip = pkt.psrc
        claimed_mac = pkt.hwsrc
        arrival_time = time.time()

        # If IP was seen before, check for inconsistencies
        if src_ip in network_state:
            original_mac, last_seen = network_state[src_ip]

            # 🔥 TIME-BASED ATTACK DETECTION
            time_difference = arrival_time - last_seen
            if time_difference < 0.5:  # Suspiciously fast responses
                log_spoofing_attempt(src_ip, claimed_mac, original_mac, "Unnaturally Fast ARP Response")

            # 🔥 MAC MISMATCH DETECTION
            if original_mac != claimed_mac:
                real_mac = get_real_mac(src_ip)
                if real_mac and real_mac != claimed_mac:
                    log_spoofing_attempt(src_ip, claimed_mac, real_mac, "MAC Address Mismatch")

        # Update network state
        network_state[src_ip] = (claimed_mac, arrival_time)

# 📖 The Tome of Digital Shadows: Logging Threats
def log_spoofing_attempt(ip, fake_mac, real_mac, reason):
    alert_message = f"\n🚨 [ALERT] ARP Spoofing Detected! 🚨\n"
    alert_message += f"Reason: {reason}\n"
    alert_message += f"🔹 IP: {ip}\n"
    alert_message += f"🔹 Fake MAC: {fake_mac} (Potential Attacker)\n"
    alert_message += f"🔹 Real MAC: {real_mac} (Expected Device)\n"
    alert_message += f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"

    print(alert_message)

    # Pretty Table for CLI Display
    table = PrettyTable(["Parameter", "Value"])
    table.add_row(["Spoofed IP", ip])
    table.add_row(["Fake MAC", fake_mac])
    table.add_row(["Real MAC", real_mac])
    table.add_row(["Reason", reason])
    table.add_row(["Timestamp", time.strftime("%Y-%m-%d %H:%M:%S")])
    print(table)

    # Save log with deeper insights
    logging.info(f"[SPOOF ATTEMPT] IP: {ip} | Fake MAC: {fake_mac} | Real MAC: {real_mac} | Reason: {reason}")

# 🌍 The Observer Begins Watching
def start_sniffing():
    print(mango_art)
    print("\n🌌 [INFO] The ARP Guardian is watching...\n")
    sniff(filter="arp", store=False, prn=analyze_arp_packet)

# 🏴‍☠️ Root Privilege Check
if os.geteuid() != 0:
    print("\n⛔ [ERROR] This script requires root privileges. Run with sudo!\n")
else:
    start_sniffing()
