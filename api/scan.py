import socket

def scan_ports(host):
    open_ports = []
    for port in range(20, 1025):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((host, port))
        if result == 0:
            open_ports.append(port)
        s.close()
    return open_ports

if __name__ == "__main__":
    host = "scanme.nmap.org"
    print(f"Scanning {host}...")
    ports = scan_ports(host)
    print("Open ports:", ports)
