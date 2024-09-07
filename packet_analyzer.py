import nmap
import pyshark
import subprocess
import threading
from queue import Queue
import os

# Global list to store online devices
online_devices = []

# Function to scan for online devices using nmap and ping scan
def scan_network(network_range):
    print(f"Scanning network {network_range} for online devices...")
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=network_range, arguments='-sn')  # Ping scan
        for host in nm.all_hosts():
            if nm[host].state() == 'up':
                print(f"Host {host} is online.")
                online_devices.append(host)
        if not online_devices:
            raise ValueError("No online devices found.")
    except Exception as e:
        print(f"Error scanning network: {e}")

# Function to scan each device for open TCP and HTTP ports using decoys and fragmented packets
def scan_ports(device_ip, decoys):
    print(f"Scanning ports on {device_ip} using decoy IPs {decoys}...")
    nm = nmap.PortScanner()
    try:
        # Decoy scan with fragmented packets
        scan_args = f'-sS -D {decoys} -f'
        nm.scan(hosts=device_ip, arguments=scan_args)
        open_ports = nm[device_ip]['tcp'].keys() if 'tcp' in nm[device_ip] else []
        if open_ports:
            print(f"Open TCP ports on {device_ip}: {open_ports}")
        else:
            print(f"No open TCP ports found on {device_ip}")
        return open_ports
    except Exception as e:
        print(f"Error scanning ports on {device_ip}: {e}")

# Function to sniff TCP and HTTP traffic for a given device using pyshark
def sniff_traffic(device_ip, interface='eth0', log_file=None):
    print(f"Sniffing TCP and HTTP traffic from {device_ip}...")
    capture = pyshark.LiveCapture(interface=interface, display_filter=f'ip.src == {device_ip} && (tcp || http)')
    
    try:
        for packet in capture.sniff_continuously():
            if 'IP' in packet:
                log_packet(log_file, packet.ip.src, packet.ip.dst)
            if 'HTTP' in packet:
                log_packet(log_file, packet.ip.src, packet.ip.dst, http_info=packet.http)
    except KeyboardInterrupt:
        print("Stopped packet sniffing.")
    except Exception as e:
        print(f"Error during traffic sniffing: {e}")

# Function to log packets to a file
def log_packet(log_file, src_ip, dst_ip, http_info=None):
    try:
        with open(log_file, 'a') as f:
            f.write(f"Packet from {src_ip} to {dst_ip}\n")
            if http_info:
                f.write(f"HTTP Packet Info: {http_info}\n")
    except Exception as e:
        print(f"Error writing to log file {log_file}: {e}")

# Function to run the full workflow for each online device (port scan + traffic sniffing)
def scan_and_sniff(device_ip, decoys, packet_limit=100):
    log_file = f"{device_ip}_traffic_log.txt"  # Create a file for each device by IP
    print(f"Logging traffic for {device_ip} in {log_file}")
    
    # Create or clear the log file
    try:
        with open(log_file, 'w') as f:
            f.write(f"Traffic log for device {device_ip}\n\n")
    except Exception as e:
        print(f"Error creating log file for {device_ip}: {e}")

    open_ports = scan_ports(device_ip, decoys)
    if open_ports:
        sniff_traffic(device_ip, log_file=log_file)

# Multi-threading worker function to handle devices in parallel
def worker(decoys):
    while True:
        device_ip = q.get()
        if device_ip is None:
            break
        scan_and_sniff(device_ip, decoys)
        q.task_done()

# Main function to orchestrate the scanning and sniffing process
def main(network_range, decoys):
    # Scan the network for online devices
    scan_network(network_range)

    if not online_devices:
        print("No online devices found. Exiting.")
        return

    # Multi-threading setup
    num_threads = min(10, len(online_devices))  # Set a limit on the number of threads
    threads = []
    global q
    q = Queue()

    # Start threads
    for i in range(num_threads):
        t = threading.Thread(target=worker, args=(decoys,))
        t.start()
        threads.append(t)

    # Add devices to the queue
    for device_ip in online_devices:
        q.put(device_ip)

    # Block until all tasks are done
    q.join()

    # Stop workers
    for i in range(num_threads):
        q.put(None)
    for t in threads:
        t.join()

if __name__ == "__main__":
    network_range = input("Enter the network range (e.g., 192.168.1.0/24): ")
    decoys = input("Enter decoy IP addresses (comma separated): ")
    
    main(network_range, decoys)