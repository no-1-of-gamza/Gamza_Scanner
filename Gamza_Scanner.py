import threading
import concurrent.futures
import socket 
import random
import sys
import time
import os
from tqdm import tqdm
import json
import argparse
from ftplib import FTP
import whois


#!랜덤소스도 고려해야할 부분!

def print_welcome_message():
    welcome_message = """
    _____                                 ______                                       
    |  __ \                               /  ___|                                       
    | |  \/  __ _  _ __ ___   ____  __ _  \ `--.   ___   __ _  _ __   _ __    ___  _ __ 
    | | __  / _` || '_ ` _ \ |_  / / _` |  `--. \ / __| / _` || '_ \ | '_ \  / _ \| '__|
    | |_\ \| (_| || | | | | | / / | (_| | /\__/ /| (__ | (_| || | | || | | ||  __/| |   
    \____/ \__,_||_| |_| |_|/___| \__,_| \____/  \___| \__,_||_| |_||_| |_| \___||_| 

    Welcome to Port Scanner!

    """
    #os.system('clear')  # 화면을 지우는 명령어 (Linux/Mac)
    print(welcome_message)

def load_rule_set(json_file_path):
    
    with open(json_file_path, 'r') as file:
        rule_data = json.load(file)
    
    print()

def parse_arguments():
    parser = argparse.ArgumentParser(description="Gamza Scanner - 포트 스캐닝 도구")
    parser.add_argument("target_host", help="대상 호스트의 IP 주소")
    parser.add_argument("-p", "--ports", nargs="+", type=int, default=range(1, 1025),
                        help="스캔할 특정 포트 번호 (공백으로 구분하여 입력)")
    parser.add_argument("-t", "--threads", type=int, default=16, help="Thread")

    parser.add_argument("-sT", "--tcp", action="store_true", default=True, help="TCP Scan")
    parser.add_argument("-sU", "--udp", action="store_true", help="UDP Scan")


    return parser.parse_args()

'''
기본 사용법: python Gamza_Scanner.py 192.168.1.1
기본 스캔 : TCP Open Scan

포트 지정: python Gamza_Scanner.py 192.168.1.1 -p 80 443 8080
스레드 수 지정: python Gamza_Scanner.py 192.168.1.1 -t 8
UDP 스캔 수행: python Gamza_Scanner.py 192.168.1.1 -sU
TCP 스캔 수행 : python Gamza_Scanner.py 192.168.1.1 -sT
'''

def tcp_scan(host, port,thread_ids):
    
    lock = threading.Lock()
    
    with lock:
        thread_id = threading.get_ident()
        thread_ids.add(thread_id)

    # time.sleep(0.5) TCP 연결 상태보고 조절 
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.15)
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

def udp_scan(host, port,thread_ids): #UDP 스캔 수정 필요
# UDP 데이터 송신 응답인증을 하지 않기 때문에 TCP랑 분리하는게좋다 
    
    lock = threading.Lock()
    
    with lock:
        thread_id = threading.get_ident()
        thread_ids.add(thread_id)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.1)
        result = sock.sendto(b'', (host, port))
        
        try:
            response, _ = sock.recvfrom(1024)  # 응답 확인
            if response:
                return thread_id, port, True, sock, None
        except socket.timeout:
            pass
        sock.close()
        sock = None
        return thread_id, port, False, sock, None
    
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
        body = "param1=value1&param2=value2"
        request = f"POST / HTTP/1.1\r\n"
        request += f"Host: {target_host}\r\n"
        request += "Content-Type: application/x-www-form-urlencoded\r\n"
        request += f"Content-Length: {len(body)}\r\n"
        request += "\r\n"
        request += body
    #sock.send(b'POST / HTTP/1.1\r\nHost: ' + target_host.encode() + b'\r\n\r\n')
    # 보내는 정보를 고도화 할 필요가 있음 악성패킷으로 인식가능
        sock.send(request.encode())
    # 배너 정보 수신
        banner = sock.recv(4096).decode().strip()
        
        banner_lines = banner.split('\n')
        banner = banner_lines[:3]

        #print(f"{banner}")
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

def multi_threading(num_threads, thread_ids, target_host, ports, scan):

    open_ports = []
    closed_ports = []
    filtered_ports = []
    Service = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(scan, target_host, port, thread_ids) for port in ports]
        total_ports = len(ports)
        with tqdm(total=total_ports, desc="Scanning Ports", unit="port") as pbar:
            for future in concurrent.futures.as_completed(futures):
                pbar.update(1)
                thread_id, port, is_open, sock, result = future.result()
                if is_open or sock is not None:
                    open_ports.append(port)
                    #포트열려있음

                    #서비스식별
                    # 배너그래빙
                    try:
                        Service[port] = banner_grabbing(target_host, port, sock)
                    except Exception as e:
                        print("An error occurred while banner grabbing:", e)
                        pass 
                    try:
                        # tcpmux 확인
                        sock.send("help\r\n".encode())
                        sock_recv= sock.recv(4096).decode()
                        if sock.recv == "+" :
                            Service[port] = {sock_recv}
                    except Exception as e:
                        #print("An error occurred while sending help request:", e)
                        pass
                    # echo 확인
                    try:
                        sock.send(b"echo")
                        sock_recv= sock.recv(4096).decode()
                        print(sock_recv)
                        if sock.recv == "echo" :
                            Service[port] = {sock_recv}
                    except Exception as e:
                        #print("An error occurred while testing echo:", e)
                        pass
                    
                


                # 차단된 포트
                elif result == 61:
                   filtered_ports.append(port)
                # 닫혀 있는 포트
                else:
                    closed_ports.append(port)

    #그래빙을 다 돌고 서비스 식별
    #서비스식별
    Service_Detected(Service)
    result_printing(thread_ids, filtered_ports, closed_ports, open_ports, Service)

def Service_Detected(Service):
    print()

def result_printing(thread_ids, filtered_ports, closed_ports,open_ports, Service):
    print("\nUsed thread IDs:")
    print(', '.join(map(str, thread_ids)))

    print(f"\nTotal used thread IDs: {len(thread_ids)}")

    closed_ports.sort()  
    open_ports.sort()   

    print("\nService Detected:")
    #print(', '.join(map(str, Service)))
    for key, value in Service.items():
        print(key, value)

    print("\nOpen ports:")
    print(', '.join(map(str, open_ports)))

    #closed 포트 비출력
    #print("\nClosed ports:")
    #print(', '.join(map(str, closed_ports)))

    #print("\nfiltered ports:")
    #print(', '.join(map(str, filtered_ports)))   

    print(f"\nTotal open ports: {len(open_ports)}")
    print(f"Total closed ports: {len(closed_ports)}")
    print(f"Total filtered ports: {len(filtered_ports)}")
    
    
def main():

    #아스키아트 출력
    print_welcome_message()

    #옵션값 가져오기
    args = parse_arguments()

    #rule_set 경로
    json_file_path = 'rule_set.json'

    # 사용자 입력값 example.py {ip}
    if len(sys.argv) < 2:
        print("\n python Gamza_Scanner.py YourIP!")
        return
    #Target_host IP 반드시 입력
    target_host = sys.argv[1]

    # Target_host IP 반드시 입력
    target_host = args.target_host

    # 사용할 스레드 개수
    num_threads = args.threads
    thread_ids = set()

    #검색할포트
    start_num = args.ports[0]
    end_num = args.ports[-1]
    ports = list(args.ports)
    random.shuffle(ports)

    if args.udp:
        # UDP 스캔 수행
        scan =udp_scan     
        multi_threading(num_threads, thread_ids, target_host, ports, scan)
        udp_scan(target_host, start_num, thread_ids)

    elif args.tcp:
        # TCP 스캔 수행
        scan =tcp_scan
        multi_threading(num_threads, thread_ids, target_host, ports, scan)
        tcp_scan(target_host, start_num, thread_ids)

    print(f"\nProtocol : TCP \nDetected Ports : {start_num}~{end_num} \nTarget Host :({target_host})\n")

if __name__ == "__main__":
    main()