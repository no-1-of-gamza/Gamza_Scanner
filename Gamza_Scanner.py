import socket 
import random

#모듈분리
from print_message import print_welcome_message
from option import option_set
from port_scan import port_scan_multi_threading, tcp_scan
from service_scan import service_scan_multi_threading

    
def main():
    #아스키아트 출력
    print_welcome_message()

    #옵션값 가져오기
    args = option_set()

    # Target_host IP 반드시 입력
    target_host = args.target_host

    # 사용할 스레드 개수
    num_threads = args.threads
    thread_ids = set()

    #검색할포트 범위
    start_num = args.ports[0]
    end_num = args.ports[-1]
    ports = list(args.ports)

    if args.tcp :
        scan = tcp_scan
    
    # 포트 스캔       
    open_ports = port_scan_multi_threading(num_threads, thread_ids, target_host, ports, scan)

    print(f"\nProtocol : TCP \nDetected Ports : {start_num}~{end_num} \nTarget Host :({target_host})\n")

    #서비스 스캔
    service_scan_multi_threading(target_host, open_ports)

if __name__ == "__main__":
    main()