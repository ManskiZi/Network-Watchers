import pyshark

def capture_traffic(ip_address):
    # Capture live packets on interface eth0 (you might need to change this to your active interface)
    capture = pyshark.LiveCapture(interface='eth0', display_filter=f'(ip.src == {ip_address} && tcp) || (ip.src == {ip_address} && http)')
    
    print(f"Capturing TCP and HTTP traffic from IP: {ip_address}")
    
    # Loop through the captured packets and print destination IP addresses
    try:
        for packet in capture.sniff_continuously(packet_count=20):  # Adjust packet count as needed
            try:
                if 'IP' in packet:
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    print(f"Packet from {src_ip} to {dst_ip}")
            except AttributeError:
                continue  # Skip packets that don't have IP layer information
    except KeyboardInterrupt:
        print("Capture stopped.")

if __name__ == '__main__':
    target_ip = input("Enter the IP address to capture traffic from: ")
    capture_traffic(target_ip)