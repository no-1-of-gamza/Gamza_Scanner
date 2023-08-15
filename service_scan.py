#Service_Scan
import socket
import threading

open_Services = []
closed_Services = []
unknown_Services = []
lock = threading.Lock()

def banner_grabbing(target_host, target_port, sock):
    try: 
        sock.send(b'POST / HTTP/1.1\r\nHost: ' + target_host.encode() + b'\r\n\r\n')
        # 보내는 정보를 고도화 할 필요가 있음 악성패킷으로 인식가능     
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

def FTP_conn(target_host, port, username, password):
    from ftplib import FTP, error_perm
    try :
        # FTP 서버 정보
        # FTP 서버에 접속
        ftp = FTP(target_host)
        ftp.login(user=username, passwd=password)
        print("FTP Connection Success")
        ftp.quit()
        return True
    except error_perm as e:
        print(f"FTP Connection Error: {e}") 
        return True
    except Exception as e:
        print(f"FTP Error: {e}")

def SSH_conn(target_host, port, username, password):
    import paramiko
    try:

        # SSH 클라이언트 객체 생성
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # SSH 서버에 접속
        ssh_client.connect(target_host, port=port, username=username, password=password)

        # 접속 성공 메시지 출력
        print("SSH Connection Success")
        # 연결 종료
        ssh_client.close()
        return True
    except paramiko.AuthenticationException:
        print("SSH Authentication fail") 
        return True
    except paramiko.SSHException as e:
        print(f"SSH Connection Error: {e}")
    except Exception as e:
        print(f"SSH Error : {e}")

def SMTP_conn(target_host, port, username, password):
    import smtplib
    from smtplib import SMTPAuthenticationError
    try:

        # SMTP 서버에 접속
        smtp_server = smtplib.SMTP(target_host, port)
        #smtp_server.starttls()
        smtp_server.login(username, password)

        # 접속 종료
        smtp_server.quit()
        return True
    except SMTPAuthenticationError as e:
        print("SMTP Authentication Error:", e)
        print("SMTP authentication is not supported by the server.")
        return True

def Daytime_conn(target_host, port, username, password):
    try:
        # 소켓 생성 및 연결
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((target_host, port))

        # 데이터 수신
        data = client_socket.recv(1024)
        daytime_data = data.decode('utf-8').strip()

        # 소켓 닫기
        client_socket.close()

        return daytime_data
    except Exception as e:
        print(f"Daytime Error: {e}")
        return None

def telnet_conn(target_host, port, username, password):
    import telnetlib
    try:
        # Telnet 서버에 연결
        tn = telnetlib.Telnet(target_host, port)

        # 연결 확인 메시지 출력
        print(f"Telnet Connection: {target_host}:{port}")
        # Telnet 세션 종료
        tn.close()
        return True
    except Exception as e:
        print(f"Telnet Error: {e}")

def DNS_conn(target_host, port, username, password):
    import dns.reversename
    import dns.resolver
    try:
        # IP 주소를 PTR 레코드 형식으로 변환
        ptr_query = dns.reversename.from_address(target_host)

        # PTR 쿼리 보내기
        result = dns.resolver.resolve(ptr_query, 'PTR')

        # 응답 출력
        for answer in result:
            print(f"Domain: {answer.target}")
        return True
    except Exception as e:
        print(f"DNS Error: {e}")

def TFTP_conn(target_host, port, username, password):
    from tftpy import TftpClient, TftpTimeout
    client = TftpClient(target_host, port)
    try:
        client = TftpClient(target_host, port)
        print("TFTP Connection Successful")
        return True
    except TftpTimeout:
        print("TFTP Connection Timed Out")      

    except Exception as e:
        print("TFTP Connection Error:", e)

def finger_conn(target_host, port, username, password):
    try:
        # 소켓 생성 및 연결
        sock = socket.create_connection((target_host, port))
        
        # 서버에 사용자 정보 요청 전송
        query = f"{username}\r\n"
        sock.send(query.encode())
        
        # 응답 수신
        response = sock.recv(4096).decode()
        
        # 소켓 연결 종료
        sock.close()    
        return True
    
    except Exception as e:
        return f"Error: {e}"

def HTTP_conn(target_host, port, username, password):
    import requests
    try:
        url = f"http://{target_host}:{port}"
        response = requests.get(url)
        response.raise_for_status()  # 응답 상태 코드 확인
     
        print("Successful connection!")
        return True
    
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
        return True
    
    except requests.exceptions.ConnectionError as conn_err:
        print(f"Connection error occurred: {conn_err}")
    
    except requests.exceptions.RequestException as req_err:
        print(f"Request error occurred: {req_err}")

def POP3_conn(target_host, port, username, password):
    import poplib
    # POP3 서버에 연결
    try:
        pop3_connection = poplib.POP3(target_host)

        # 계정 로그인
        pop3_connection.user(username)
        pop3_connection.pass_(password)
                # 연결 및 로그인 성공 시, pop3_connection을 반환
        return True

    except poplib.error_proto as e:
        print("POP3 연결 또는 로그인 오류:", e)
        return True
    except Exception as e:
        print("알 수 없는 오류:", e)
        return None

def Sunrpc_conn(target_host, port, username, password):
    import xmlrpc.client

    try:
        # SunRPC 서버의 주소와 포트
        server_address = f"{target_host}:{port}"

        # XML-RPC 클라이언트 생성
        client = xmlrpc.client.ServerProxy(server_address)

        return True

    except xmlrpc.client.Fault as e:
        print("SunRPC 에러:", e.faultString)
        return True
    except ConnectionError as e:
        print("연결 오류:", e)
        return True
    except Exception as e:
        print("알 수 없는 오류:", e)
        return None
  
def NNTP_conn(target_host, port, username, password):
    
    import nntplib
    # NNTP 서버 정보
    server_address = target_host
    # NNTP 서버에 연결
    try:
        nntp_connection = nntplib.NNTP(server_address)
        return True
    except nntplib.NNTPError as e:
        print("NNTP 에러:", e)
        return True
    except Exception as e:
        print("알 수 없는 오류:", e)
    finally:
        nntp_connection.quit()

def NetBIOS_conn(target_host, port, username, password):
    from impacket.smbconnection import SMBConnection
    service_name=nmb
    conn = nmb.NetBIOS()
    try:
        remote_name = nmb.NetBIOS.queryIPForName(target_host)
        if remote_name:
            remote_name = remote_name[0]
            print(f"Connecting to service '{service_name}' on {remote_name} ({target_host})")
            
            session = conn.connect(remote_name, service_name)
            if session:
                print("Connection successful!")
                return True

        else:
            print("Unable to resolve IP address to NetBIOS name.")

    except nmb.NetBIOSTimeout as e:
        print("Connection timeout:", e)
    except Exception as e:
        print("Error:", e)
    finally:
        conn.close()

def main():
    port_list = [13, 21, 22, 23, 25, 53, 69, 79, 80]
    target_host = "162.212.101.163"
    threads = []
    service_functions = [
        Daytime_conn, FTP_conn, SSH_conn, telnet_conn,
        SMTP_conn, DNS_conn, TFTP_conn, finger_conn, HTTP_conn
    ]

    username = "username"
    password = "password"
    
    port = 137

    #Daytime_conn(target_host, port) #13
    #FTP_conn(target_host, port, username, password) #21
    #SSH_conn(target_host, port, username, password) #22
    #telnet_conn(target_host, port) #23
    #SMTP_conn(target_host, port, username, password) #25
    #DNS_conn(target_host, port, username, password) #53
    #TFTP_conn(target_host, port) #69
    #finger_conn(target_host, port, username) #79
    #HTTP_conn(target_host, port, username, password) #80
    #POP3_conn(target_host, port, username, password) #110
    #Sunrpc_conn(target_host, port, username, password)#111
    #NNTP_conn(target_host, port, username, password)#119
    NetBIOS_conn(target_host, port, username, password)


                
if __name__ == "__main__":
    main()




