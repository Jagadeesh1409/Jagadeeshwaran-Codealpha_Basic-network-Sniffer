# Jagadeeshwaran-Codealpha_Basic-network-Sniffer

TASK-1 BASIC NETWORK SNIFFER
          
from scapy.all import sniff, TCP, UDP, ICMP, IP, Raw

# Define a function to process each packet
def packet_callback(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            src_port = ""
            dst_port = ""
        else:
            protocol = "Other"
            src_port = ""
            dst_port = ""

        # Check if the packet has a payload
        if packet.haslayer(Raw):
            payload = packet[Raw].load
        else:
            payload = ""

        # Print the packet information
        packet_info = f"Source IP: {src_ip} | Destination IP: {dst_ip} | Protocol: {protocol} | Source Port: {src_port} | Destination Port: {dst_port} | Payload: {payload}"
        print(packet_info)
        # Copy the packet info to clipboard (optional)
        try:
            import pyperclip
            pyperclip.copy(packet_info)
            print("Packet info copied to clipboard.")
        except ImportError:
            print("Install pyperclip library to copy packet info to clipboard.")

# Start sniffing packets
sniff(prn=packet_callback, count=100, store=False)



SAMPLE OUTPUT:
Packet Captured:
Source IP: 192.168.1.10
Destination IP: 8.8.8.8
Protocol: 17
Payload: b'\x03\x0fExamplePayloadData'

Packet Captured:
Source IP: 192.168.1.5
Destination IP: 192.168.1.1
Protocol: 6
Payload: b'GET /index.html HTTP/1.1\r\nHost: example.com\r\n'
