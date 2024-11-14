from scapy.all import sniff

def packet_callback(packet):
    # Process the packet here and return relevant information
    print(f"Captured packet: {packet.summary()}")
    return str(packet.summary())  # You can change this to any data you'd like to capture

def start_sniffing():
    # Capture 10 packets and return them
    sniffed_packets = sniff(prn=packet_callback, count=10, filter="ip")  # Capture 10 packets
    # Return the captured packets or any specific data from them
    return [str(packet.summary()) for packet in sniffed_packets]  # 