import threading
import concurrent.futures
import socket 
import random
import sys
import time
import os
from tqdm import tqdm
import json


def print_welcome_message():
    welcome_message = """
    _____                                 ______                                       
    |  __ \                               /  ___|                                       
    | |  \/  __ _  _ __ ___   ____  __ _  \ `--.   ___   __ _  _ __   _ __    ___  _ __ 
    | | __  / _` || '_ ` _ \ |_  / / _` |  `--. \ / __| / _` || '_ \ | '_ \  / _ \| '__|
    | |_\ \| (_| || | | | | | / / | (_| | /\__/ /| (__ | (_| || | | || | | ||  __/| |   
    \____/ \__,_||_| |_| |_|/___| \__,_| \____/  \___| \__,_||_| |_||_| |_| \___||_| 

    Welcome to Port Scanner!

    Scanning for Well-Known Port

    """
    #os.system('clear')  # 화면을 지우는 명령어 (Linux/Mac)
    print(welcome_message)

def load_rule_set(json_file_path):
    
    with open(json_file_path, 'r') as file:
        rule_data = json.load(file)
    
    print()



def tcp_scan(host, port,thread_ids):
    
    lock = threading.Lock()
    
    with lock:
        thread_id = threading.get_ident()
        thread_ids.add(thread_id)

    # time.sleep(0.5) TCP 연결 상태보고 조절 
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        result = sock.connect_ex((host, port))
        if result == 0:
            return thread_id, port, True, sock
        else:
            sock.close()
            sock = None
            return thread_id, port, False, sock
    except KeyboardInterrupt:
        print("\nExiting program.")
        sys.exit()
    except socket.gaierror:
        print("Hostname could not be resolved.")
        sys.exit()
    except socket.error:
        print("Couldn't connect to server.")
        sys.exit()

def banner_grabbing(target_host, target_port, sock):
    try:
    # Get을 하지 않으면 서버에서 응답을 하지 않음 
        sock.send(b'GET / HTTP/1.1\r\nHost: ' + target_host.encode() + b'\r\n\r\n')
    # 배너 정보 수신
        banner = sock.recv(1024).decode().strip()
        banner_lines = banner.split('\n')
        banner = banner_lines[:3]

        print(f"{banner}")
        return banner
    
    except ConnectionRefusedError:
        print(f"Connection refused: {target_host}:{target_port}")
    except socket.timeout:
        print(f"Connection timeout: {target_host}:{target_port}")
    except socket.error as e:
        print(f"Error: {e}")
    finally:
    # 소켓 종료
        sock.close()

def multi_threading(num_threads, thread_ids, target_host, ports):
    open_ports = []
    closed_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(tcp_scan, target_host, port, thread_ids) for port in ports]
        total_ports = len(ports)

        with tqdm(total=total_ports, desc="Scanning Ports", unit="port") as pbar:
            for future in concurrent.futures.as_completed(futures):
                pbar.update(1)
                thread_id, port, is_open, sock = future.result()
                if is_open or sock is not None:
                    open_ports.append(port)
                    banner_grabbing(target_host, port, sock)
                else:
                    closed_ports.append(port)
    result_printing(thread_ids, closed_ports, open_ports)

def result_printing(thread_ids,closed_ports,open_ports):
    print("\nUsed thread IDs:")
    print(', '.join(map(str, thread_ids)))

    print(f"\nTotal used thread IDs: {len(thread_ids)}")

    closed_ports.sort()  
    open_ports.sort()   

    #closed 포트 비출력
    #print("\nClosed ports:")
    #print(', '.join(map(str, closed_ports)))

    print("\nOpen ports:")
    print(', '.join(map(str, open_ports)))
    print(f"Total open ports: {len(open_ports)}")

    print(f"Total closed ports: {len(closed_ports)}")
    
def main():

    #아스키아트 출력
    print_welcome_message()

    #rule_set 경로
    json_file_path = 'rule_set.json'

    # 사용자 입력값 example.py {ip}
    if len(sys.argv) < 2:
        print("\n python Gamza_Scanner.py YourIP!")
        return
    #사용지 지정 포트
    start_num = 1
    end_num = 1024
    ports = list(range(start_num, end_num + 1))
    # 식별 우선순위 (잘알려진 서비스 ex)HTTP, SSH)
    random.shuffle(ports)

    #Target_host IP
    target_host = sys.argv[1]

    #사용할 스레드 개수
    num_threads = 16 #기본적으로 16개고정
    thread_ids = set()

    multi_threading(num_threads,thread_ids,target_host,ports)
    tcp_scan(target_host,start_num,thread_ids)
    print(f"\nDetected : {start_num} - {end_num} port in {target_host}\n")

if __name__ == "__main__":
    main()