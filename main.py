#instal scapy  pkgs
!pip install scapy


# Import necessary libraries
from scapy.all import sniff, IP, TCP, UDP, ARP

# Define a function to process captured packets
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        if TCP in packet:
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        else:
            proto = "Other"
            sport = None
            dport = None

        print(f"[{proto}] {ip_src}:{sport} -> {ip_dst}:{dport}")
    
    elif ARP in packet:
        arp_op = packet[ARP].op
        arp_src_ip = packet[ARP].psrc
        arp_dst_ip = packet[ARP].pdst
        if arp_op == 1:
            print(f"[ARP] Request: {arp_src_ip} is asking about {arp_dst_ip}")
        elif arp_op == 2:
            print(f"[ARP] Reply: {arp_src_ip} has address {arp_dst_ip}")

# Start the packet sniffer
def start_sniffer(interface):
    print(f"Starting packet sniffer on interface {interface}...")
    sniff(iface=interface, prn=packet_callback, store=False)

# Define the interface you want to sniff on
# For example, on Linux it might be 'eth0', 'wlan0', etc.
# On Windows, you might use the name of the network interface as shown in your network settings
interface = "eth0"

# Start the sniffer (this will run indefinitely)
start_sniffer(interface)
