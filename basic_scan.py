import nmap

def scan_IP(ip):
    scanner = nmap.PortScanner()
    scan_args = f'-sn -sS -p 1-1000'
    
    if not ip:
        print("No IP address provided. Exiting")
        return
    
    try:
        scanner.scan(hosts=ip, arguments=scan_args)
    except Exception as e:
        print(f"An error occured: {e}")
    
    if len(scanner.all_hosts()) <= 0:
        print("No hosts found")
    else:
        for host in scanner.all_hosts():
            print(f"Host: {host} ({scanner[host].hostname()})")
            print(f"State: {scanner[host].state()}")
            
            for proto in scanner[host].all_protocols():
                print(f"Protocol: {proto}")
                ports = scanner[host][proto].keys()
            
                for port in ports:
                    print(f"Port: {port}, State: {scanner[host][proto][port]['state']}")

if __name__ == "__main__":
    target_ip = input("Enter the ip address to scan: ")
    scan_IP(target_ip)

