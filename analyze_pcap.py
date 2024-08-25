import pyshark

def analyze_pcap(file_name):
    cap = pyshark.FileCapture(file_name)
    for packet in cap:
        print(f"Packet: {packet}")

if __name__ == "__main__":
    file_name = "capture.pcap"
    analyze_pcap(file_name)

