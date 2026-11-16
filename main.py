
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, Raw

from detector import load_rules, detect_suspicious_traffic


def log_alert(alert, source_ip, destination_ip):
    """Display and save detected security alerts."""

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    message = (
        f"[{timestamp}] "
        f"[{alert['severity']}] "
        f"{alert['name']} | "
        f"Source: {source_ip} | "
        f"Destination: {destination_ip} | "
        f"Pattern: {alert['matched_pattern']}"
    )

    print("\n[!] SECURITY ALERT")
    print(message)

    with open("alerts.log", "a", encoding="utf-8") as file:
        file.write(message + "\n")


def process_packet(packet, rules):
    """Analyze captured network packets."""

    if not packet.haslayer(IP):
        return

    source_ip = packet[IP].src
    destination_ip = packet[IP].dst

    protocol = "OTHER"

    if packet.haslayer(TCP):
        protocol = "TCP"
    elif packet.haslayer(UDP):
        protocol = "UDP"

    print(
        f"[PACKET] {source_ip} -> "
        f"{destination_ip} | {protocol}"
    )

    if packet.haslayer(Raw):
        payload = bytes(packet[Raw].load).decode(
            "latin-1", errors="ignore"
        )

        alerts = detect_suspicious_traffic(payload, rules)

        for alert in alerts:
            log_alert(alert, source_ip, destination_ip)


def start_ids():
    print("=" * 50)
    print(" SIGNATURE-BASED INTRUSION DETECTION SYSTEM")
    print("=" * 50)

    rules = load_rules()

    if not rules:
        print("[ERROR] No detection rules loaded.")
        return

    print(f"[INFO] Loaded {len(rules)} detection rules.")
    print("[INFO] Starting packet monitoring...")
    print("[INFO] Press CTRL+C to stop.")

    try:
        sniff(
            filter="ip",
            prn=lambda packet: process_packet(packet, rules),
            store=False
        )

    except KeyboardInterrupt:
        print("\n[INFO] IDS monitoring stopped.")

    except Exception as error:
        print(f"\n[ERROR] {error}")


if __name__ == "__main__":
    start_ids()
