import threading
import concurrent.futures
import socket 
import random
import sys
import time
import os
from tqdm import tqdm


def print_welcome_message():
    welcome_message = """
    ______                                _______                                       
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


def tcp_scan(host, port,thread_ids):
    
    lock = threading.Lock()
    
    with lock:
        thread_id = threading.get_ident()
        thread_ids.add(thread_id)

    time.sleep(0.5)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            return thread_id, port, True
        else:
            return thread_id, port, False
    except KeyboardInterrupt:
        print("\nExiting program.")
        sys.exit()
    except socket.gaierror:
        print("Hostname could not be resolved.")
        sys.exit()
    except socket.error:
        print("Couldn't connect to server.")
        sys.exit()

def multi_threading(num_threads,thread_ids,target_host,ports):
    
    open_ports = []
    closed_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(tcp_scan, target_host, port, thread_ids) for port in ports]
        total_ports = len(ports)

        with tqdm(total=total_ports, desc="Scanning Ports", unit="port") as pbar:
            for future in concurrent.futures.as_completed(futures):
                pbar.update(1)
                thread_id, port, is_open = future.result()
                if is_open:
                    open_ports.append(port)
                else:
                    closed_ports.append(port)
                #print( f"has finished scanning port {port}") 
                    

    result_printing(thread_ids,closed_ports,open_ports)

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

    print(f"Total closed ports: {len(closed_ports)}")
    print(f"\nTotal open ports: {len(open_ports)}")

def main():

    #아스키아트 출력
    print_welcome_message()

    # 사용자 입력값 example.py {ip}
    if len(sys.argv) < 2:
        print(" : python example.py YourIP!")
        return
    #사용지 지정 포트
    start_num = 1
    end_num = 1024
    ports = list(range(start_num, end_num + 1))
    # 식별 우선순위 (잘알려진 서비스 ex)HTTP, SSH)
    random.shuffle(ports)

    #Target_host IP
    target_host = 'localhost' #기본적으로 로컬 호스트
    target_host = sys.argv[1]
    # 입력값을 활용한 프로그램 로직 추가


    # 멀티스레딩 카운트 및 레이스컨디션 방지 글로벌 변수로 선언 해야함 
    #사용할 스레드 개수
    num_threads = 30 #기본적으로 16개고정
    thread_ids = set()

    multi_threading(num_threads,thread_ids,target_host,ports)
    tcp_scan(target_host,start_num,thread_ids)

if __name__ == "__main__":
    main()