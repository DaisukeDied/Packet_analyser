import logging
import os
from collections import Counter
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, Raw

try:
    import matplotlib
    matplotlib.use('TkAgg')  # Explicitly choose the Tkinter backend for matplotlib
    import matplotlib.pyplot as plt
except ImportError:
    plt = None

# Setup logging
logging.basicConfig(filename="packet_log.txt", level=logging.INFO, format="%(asctime)s %(message)s")

packet_counts = Counter()
blocked_ips = set()
warning_messages = []

def send_warning(message):
    warning_messages.append(message)
    logging.warning(message)

def block_ip(ip_address):
    if ip_address not in blocked_ips:
        os.system(f"netsh advfirewall firewall add rule name=\"Block {ip_address}\" dir=in action=block remoteip={ip_address}")
        blocked_ips.add(ip_address)
        logging.info(f"Blocked IP: {ip_address}")

def analyze_packet(packet):
    log_message = "Packet captured:\n"

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        log_message += f"IP Packet: {ip_layer.src} -> {ip_layer.dst}\n"
        
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            packet_counts['TCP'] += 1
            log_message += f"TCP Packet: {tcp_layer.sport} -> {tcp_layer.dport}\n"
            log_message += f"Flags: {tcp_layer.flags}\n"
            log_message += f"Sequence Number: {tcp_layer.seq}\n"
            log_message += f"Acknowledgment Number: {tcp_layer.ack}\n"
            if tcp_layer.dport == 80 or tcp_layer.sport == 80:
                log_message += "HTTP Packet Detected\n"
                if packet.haslayer(Raw):
                    payload = packet[Raw].load
                    log_message += f"HTTP Payload: {payload.decode(errors='ignore')}\n"
                send_warning("HTTP Packet Detected: Potentially suspicious HTTP traffic detected.")

        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            packet_counts['UDP'] += 1
            log_message += f"UDP Packet: {udp_layer.sport} -> {udp_layer.dport}\n"
            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                dns_layer = packet[DNS]
                log_message += f"DNS Query: {dns_layer.qd.qname.decode()}\n"
                send_warning("DNS Packet Detected: Potentially suspicious DNS traffic detected.")

        elif packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            packet_counts['ICMP'] += 1
            log_message += f"ICMP Packet: Type: {icmp_layer.type}, Code: {icmp_layer.code}, Src: {packet[IP].src}, Dst: {packet[IP].dst}\n"
            send_warning("ICMP Packet Detected: ICMP traffic detected, could be a ping scan.")
            if ip_layer.src == '192.168.2.113':  # Example IP to block
                block_ip(ip_layer.src)

        else:
            packet_counts['Other'] += 1

    elif packet.haslayer(ARP):
        arp_layer = packet[ARP]
        log_message += f"ARP Packet: {arp_layer.psrc} -> {arp_layer.pdst}\n"
        packet_counts['ARP'] += 1

    log_message += "\n" + "-"*50 + "\n"
    logging.info(log_message)
    print(log_message)

def start_sniffing(interface=None, packet_count=100):
    print(f"Starting packet sniffing on interface {interface}...")
    sniff(iface=interface, prn=analyze_packet, count=packet_count, filter="icmp or arp or tcp or udp")

    if plt:
        # Plot the results if matplotlib is available
        labels, values = zip(*packet_counts.items())
        plt.bar(labels, values)
        plt.xlabel('Packet Type')
        plt.ylabel('Count')
        plt.title('Packet Count by Type')
        plt.show()
    else:
        print("matplotlib is not available. Skipping the plot.")

    if warning_messages:
        print("WARNING:")
        for message in warning_messages:
            print(message)

if __name__ == "__main__":
    interface = input("Enter the interface to sniff on (or leave blank for default): ")
    packet_count = int(input("Enter the number of packets to sniff: "))
    start_sniffing(interface=interface if interface else None, packet_count=packet_count)
