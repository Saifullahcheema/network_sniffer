from scapy.all import *
def packet_callback(packet):
    print(f"Packet: {packet.summary()}")
    wrpcap('capture.pcap', packet, append=True)
def start_sniffing(interface):
    print(f"Starting sniffer on interface: {interface}")
    sniff(iface=interface, prn=packet_callback, store=0)
if __name__ == "__main__":
    interface = "eth0"
    start_sniffing(interface)

