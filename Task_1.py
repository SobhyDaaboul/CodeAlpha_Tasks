from scapy.all import sniff, IP, TCP, UDP, ICMP

def analyze_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        proto = ip_layer.proto

        if proto == 6 and TCP in packet:  # TCP
            print(f"[TCP] {src} --> {dst} | Port: {packet[TCP].sport} -> {packet[TCP].dport}")
        elif proto == 17 and UDP in packet:  # UDP
            print(f"[UDP] {src} --> {dst} | Port: {packet[UDP].sport} -> {packet[UDP].dport}")
        elif proto == 1 and ICMP in packet:  # ICMP
            print(f"[ICMP] {src} --> {dst}")
        else:
            print(f"[IP] {src} --> {dst} | Protocol: {proto}")
    else:
        print("Non-IP packet")

# Start sniffing on interface (default will sniff all)
print("Starting network sniffer... Press Ctrl+C to stop.")
sniff(prn=analyze_packet, store=False)
