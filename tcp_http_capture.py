import pyshark

def capture_traffic(ip_address, packet_limit):
    # Capture live packets on the specified interface
    capture = pyshark.LiveCapture(interface='eth0', display_filter=f'ip.src == {ip_address}')
    
    print(f"Capturing traffic (TCP, HTTP, HTTPS) from IP: {ip_address}")
    
    packet_count = 0
    
    # Loop through the captured packets and print destination IP addresses
    try:
        for packet in capture.sniff_continuously():
            try:
                if 'IP' in packet:
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    protocol = packet.transport_layer if hasattr(packet, 'transport_layer') else 'Unknown'
                    
                    # Print packet details immediately
                    print(f"Packet from {src_ip} to {dst_ip} using protocol {protocol}")
                    packet_count += 1
                    
                    if packet_count >= packet_limit:
                        print(f"Packet limit of {packet_limit} reached. Stopping capture.")
                        break
            except AttributeError:
                continue  # Skip packets that don't have IP layer information
    except KeyboardInterrupt:
        print("Capture stopped by user.")

if __name__ == '__main__':
    target_ip = input("Enter the IP address to capture traffic from: ")
    packet_limit = int(input("Enter the packet limit: "))
    
    capture_traffic(target_ip, packet_limit)