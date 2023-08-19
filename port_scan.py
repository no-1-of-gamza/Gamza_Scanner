#port_scan
import socket
import threading
import sys
import concurrent.futures
from tqdm import tqdm
import random

from print_message import port_result_printing

def port_scan_multi_threading(num_threads, thread_ids, target_host, ports, scan):
    
    random.shuffle(ports)

    open_ports = []
    closed_ports = []
    filtered_ports = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(scan, target_host, port, thread_ids) for port in ports]
        total_ports = len(ports)
        with tqdm(total=total_ports, desc="Scanning Ports", unit="port") as pbar:
            for future in concurrent.futures.as_completed(futures):
                pbar.update(1)
                thread_id, port, is_open, sock, result = future.result()
                if is_open or sock is not None:
                    open_ports.append(port)
                # 차단된 포트
                elif result == 61:
                   filtered_ports.append(port)
                # 닫혀 있는 포트
                else:
                    closed_ports.append(port)

    port_result_printing(thread_ids, filtered_ports, closed_ports, open_ports)
    

    return open_ports


def tcp_scan(host, port,thread_ids):

    scan =tcp_scan

    lock = threading.Lock()
    
    with lock:
        thread_id = threading.get_ident()
        thread_ids.add(thread_id)

    # time.sleep(0.5) TCP 연결 상태보고 조절 
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            return thread_id, port, True, sock, result
        elif result == 61:
            sock.close()
            sock = None
            return thread_id, port, False, sock, result
        else:
            sock.close()
            sock = None
            return thread_id, port, False, sock, result
    except KeyboardInterrupt:
        print("\nExiting program.")
        sys.exit()
    except socket.gaierror:
        print("Hostname could not be resolved.")
        sys.exit()
    except socket.error:
        print("Couldn't connect to server.")
        sys.exit()
    finally:
        if sock:
            sock.close()