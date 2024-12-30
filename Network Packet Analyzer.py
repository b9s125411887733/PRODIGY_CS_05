import scapy.all as scapy
import logging
import time

# Set up logging to ensure the ethical use of the tool
logging.basicConfig(filename="packet_sniffer.log", level=logging.INFO,
                    format='%(asctime)s - %(message)s')

def analyze_packet(packet):
    """
    This function is used to analyze the captured packets and display relevant information.
    """
    try:
        if packet.haslayer(scapy.IP):  # Check if the packet has an IP layer
            ip_src = packet[scapy.IP].src
            ip_dst = packet[scapy.IP].dst
            protocol = packet[scapy.IP].proto
            payload = packet.payload

            # Display basic packet info
            print(f"Source IP: {ip_src}")
            print(f"Destination IP: {ip_dst}")
            print(f"Protocol: {protocol}")
            print(f"Payload: {payload}")

            # Log the packet details for ethical use (to analyze later if needed)
            logging.info(f"Source IP: {ip_src}, Destination IP: {ip_dst}, Protocol: {protocol}, Payload: {payload}")

    except Exception as e:
        print(f"Error analyzing packet: {e}")

def packet_sniffer():
    """
    Main function that captures and analyzes network packets.
    """
    print("Starting the packet sniffer...")
    print("Press Ctrl+C to stop.")

    try:
        # Start sniffing the network and pass the captured packets to analyze_packet function
        scapy.sniff(prn=analyze_packet, store=False)
    except KeyboardInterrupt:
        print("\nPacket sniffing stopped by user.")
        print("Ethical use of the tool has been ensured by logging the packets.")
        exit(0)

if __name__ == "__main__":
    packet_sniffer()
