import socket

target_host = "127.0.0.1"
target_ports = range(1, 1025)

def scan_ports(host, ports):
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        
        result = sock.connect_ex((host, port))
        if result == 0:
            service = get_service_name(port)
            print(f"Port {port} is open ({service})")
        else:
            print(f"Port {port} is closed")
        
        sock.close()

def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except:
        return "Unknown service"

if __name__ == "__main__":
    scan_ports(target_host, target_ports)
