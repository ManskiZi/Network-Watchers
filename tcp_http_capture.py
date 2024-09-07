import pyshark

def capture_traffic(ip_address, packet_limit):
    # Capture live packets on interface eth0 (you might need to change this to your active interface)
    capture = pyshark.LiveCapture(interface='eth0', display_filter=f'(ip.src == {ip_address} && tcp) || (ip.src == {ip_address} && http) || (ip.src == {ip_address} && tls)')
    
    print(f"Capturing TCP, HTTP, and HTTPS traffic from IP: {ip_address}")

    # Packet capture loop
    try:
        for packet in capture.sniff_continuously(packet_count=packet_limit):
            try:
                if 'IP' in packet:
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    protocol = packet.transport_layer  # Get protocol (TCP, TLS)
                    
                    # Print packet details immediately as they are captured
                    print(f"Packet: {protocol} from {src_ip} to {dst_ip}")
                    
                    # If it's an HTTPS (TLS) packet, print additional information
                    if 'TLS' in packet:
                        print(f"  - HTTPS/TLS packet with SNI: {packet.tls.handshake_extensions_server_name}")
                
                # For HTTP traffic, print additional metadata
                if 'HTTP' in packet:
                    if 'host' in packet.http.field_names:
                        host = packet.http.host
                        print(f"  - HTTP Host: {host}")
                        
                    if 'user_agent' in packet.http.field_names:
                        user_agent = packet.http.user_agent
                        print(f"  - User Agent: {user_agent}")
                        
            except AttributeError:
                continue  # Skip packets that don't have IP or HTTP layer information
    except KeyboardInterrupt:
        print("\nCapture stopped.")

if __name__ == '__main__':
    target_ip = input("Enter the IP address to capture traffic from: ")
    packet_limit = int(input("Enter the number of packets to capture: "))  # Ask for packet limit
    capture_traffic(target_ip, packet_limit)