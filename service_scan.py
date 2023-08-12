import socket
Service = {}

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
        ftp = FTP(target_host, port=port)
        ftp.login(user=username, passwd=password)
        print("FTP Connection Success!")
        ftp.quit()
    except error_perm as e:
        print(f"FTP Connection Error: {e}")
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
    except paramiko.AuthenticationException:
        print("SSH Authentication fail") #서비스있음
    except paramiko.SSHException as e:
        print(f"SSH Connection Error: {e}")
    except Exception as e:
        print(f"SSH Error : {e}")

def SMTP_conn(target_host, port, username, password):
    import smtplib
    try:

        # SMTP 서버에 접속
        smtp_server = smtplib.SMTP(target_host, port)
        smtp_server.starttls()
        smtp_server.login(username, password)

        # 접속 종료
        smtp_server.quit()

    except Exception as e:
        print(f"SMTP Error: {e}")

def Daytime_conn(target_host, port):
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


def telnet_connect(target_host, port):
    import telnetlib
    try:
        # Telnet 서버에 연결
        tn = telnetlib.Telnet(target_host, port)

        # 연결 확인 메시지 출력
        print(f"Telnet Connection: {target_host}:{port}")

        # Telnet 세션 종료
        tn.close()
    except Exception as e:
        print(f"Telnet Error: {e}")


def main():

    username = "username"
    password = "password"
    target_host = "127.0.0.1"
    port = 587

    #FTP_conn(target_host, port, username, password)
    #SSH_conn(target_host, port, username, password)
    #SMTP_conn(target_host, port, username, password)
    #Daytime_conn(target_host, port)


if __name__ == "__main__":
    main()