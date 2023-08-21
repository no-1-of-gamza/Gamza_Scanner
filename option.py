import argparse
def option_set():
    parser = argparse.ArgumentParser(description="Gamza Scanner - 포트 스캐닝 도구")
    parser.add_argument("target_host", help="대상 호스트의 IP 주소")
    parser.add_argument("-p", "--ports", nargs="+", type=int, default=range(1, 100),
                        help="스캔할 특정 포트 번호 (공백으로 구분하여 입력)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Thread")
    parser.add_argument("-sT", "--tcp", action="store_true", default=True, help="TCP Scan")
    '''
    기본 사용법: python Gamza_Scanner.py 192.168.1.1
    기본 스캔 : TCP Open Scan
    포트 지정: python Gamza_Scanner.py 192.168.1.1 -p 80 443 8080
    스레드 수 지정: python Gamza_Scanner.py 192.168.1.1 -t 8
    TCP 스캔 수행 : python Gamza_Scanner.py 192.168.1.1 -sT
    '''
    return parser.parse_args()

