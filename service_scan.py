#Service_Scan
import socket
import threading
import concurrent.futures
from print_message import service_result_printing
from tqdm import tqdm 


lock = threading.Lock()

def banner_grabbing(target_host, target_port, sock):
    try: 
        sock.send(b'POST / HTTP/1.1\r\nHost: ' + target_host.encode() + b'\r\n\r\n')
        banner = sock.recv(4096).decode().strip()
        
        banner_lines = banner.split('\n')
        banner = banner_lines[:3]

        #print(f"{banner}")
        return banner   
    except ConnectionRefusedError:
        #print(f"Connection refused: {target_host}:{target_port}")
        pass
    except socket.timeout:
        #print(f"Connection timeout: {target_host}:{target_port}")
        pass
    except socket.error as e:
        #print(f"Error: {e}")
        pass
    finally:
        sock.close()

def FTP_conn(target_host, port, username, password):
    import ftplib
    service_name = "FTP"
    from ftplib import FTP
    try:
        ftp = FTP(target_host)
        ftp.login(user=username, passwd=password)
        #print("FTP Connection Success")
        ftp.quit()
        return (True, service_name)
    except ftplib.error_perm as e:
        #print(f"FTP Authentication Error: {e}")
        return ("Closed", service_name)
    except Exception as e:
        #print(f"FTP Error: {e}")
        return (None, service_name)

def SSH_conn(target_host, port, username, password):
    import paramiko

    service_name="SSH"
    try:
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        timeout = 10
        ssh_client.connect(target_host, port=port, username=username, password=password, timeout=timeout,banner_timeout=timeout,auth_timeout=timeout, TimeoutError=False)
        
        #print("SSH Connection Success")
        ssh_client.close()
        return (True, service_name)
    except paramiko.AuthenticationException as e:
        #print("SSH Authentication fail")
        return (True, service_name)
    except paramiko.SSHException as ssh_error:
        return (None, service_name)
    except Exception as e:
        #print(f"SSH Error : {e}")
        return (None, service_name)

def SMTP_conn(target_host, port, username, password):
    import smtplib
    from smtplib import SMTPAuthenticationError
    service_name="SMTP"
    try:
        smtp_server = smtplib.SMTP(target_host, port)
        smtp_server.login(username, password)

        smtp_server.quit()
        return (True, service_name)
    except SMTPAuthenticationError as e:
        #print("SMTP Authentication Error:", e)
        #print("SMTP authentication is not supported by the server.")
        return (True, service_name)
    except Exception as e:
        return (None, service_name)

def Daytime_conn(target_host, port, username, password):
    import re
    service_name="Daytime"
    try: 
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((target_host, port))

        data = client_socket.recv(1024)
        daytime_data = data.decode('utf-8').strip()
        client_socket.close()
        pattern = r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"

    # 정규 표현식으로 시간 정보 추출
        match = re.search(pattern, daytime_data)
        if match:
            extracted_time = match.group(1)
            #print(f"Extracted Time: {extracted_time}")
            return (True, service_name)
        else:
            #print("No matching time found")
            return (None, service_name)     
    except Exception as e:
        print(f"Daytime Error: {e}")
        return (None, service_name)

def telnet_conn(target_host, port, username, password):
    import telnetlib
    service_name="telnet"
    try:
        tn = telnetlib.Telnet(target_host, port) 
        tn.read_until(b"login: ") 
        tn.write(username.encode('utf-8') + b"\n") 
        tn.read_until(b"Password: ")  
        tn.write(password.encode('utf-8') + b"\n")  
        tn.read_until(b"$ ")  

        tn.write(b"ls -l\n")
        result = tn.read_until(b"$ ").decode('utf-8')

        tn.close()
        print(f"tn : {tn}")
        if tn is not None:
            return (True, service_name)
        else : 
            return (None, service_name)
    except Exception as e:
        #print(f"Telnet Error: {e}")
        return (None, service_name)

def DNS_conn(target_host, port, username, password):
    import dns.reversename
    import dns.resolver
    service_name="DNS"
    try:
        ptr_query = dns.reversename.from_address(target_host)
        result = dns.resolver.resolve(ptr_query, 'PTR')
        val = "SMTP" in result
        if val :
            return (True, "SMTP")
        else :
            return (True, service_name)

    except Exception as e:
        #print(f"DNS Error: {e}")
        return (None, service_name)

def TFTP_conn(target_host, port, username, password):
    from tftpy import TftpClient, TftpTimeout
    service_name="TFTP"
    try:
        client = TftpClient(target_host, port)
        #print("TFTP Connection Successful")
        if client:
            return (True, service_name)
        else :
            return (None, service_name)
    except TftpTimeout:
        #print("TFTP Connection Timed Out")
        return (None, service_name)

    except Exception as e:
        #print("TFTP Connection Error:", e)
        return (None, service_name)

def finger_conn(target_host, port, username, password):
    service_name="finger"
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
        return (True, service_name)
    
    except Exception as e:
        return (None, service_name)

def HTTP_conn(target_host, port, username, password):
    import requests
    service_name="HTTP"
    try:
        url = f"http://{target_host}:{port}"
        response = requests.get(url)
        #response.raise_for_status()  # 응답 상태 코드 확인
        socket.setdefaulttimeout(5)  
        #print("Successful connection!")
        return (True, service_name)
    
    except requests.exceptions.HTTPError as http_err:
        #print(f"HTTP error occurred: {http_err}")
        return (None, service_name)
    
    except requests.exceptions.ConnectionError as conn_err:
        #print(f"Connection error occurred: {conn_err}")
        return (None, service_name)
    
    except requests.exceptions.RequestException as req_err:
        #print(f"Request error occurred: {req_err}")
        return (None, service_name)

def POP3_conn(target_host, port, username, password):
    import poplib
    # POP3 서버에 연결
    service_name="POP3"
    try:
        pop3_connection = poplib.POP3(target_host)
        pop3_connection.user(username)
        pop3_connection.pass_(password)
        return (True, service_name)

    except poplib.error_proto as e:
        return (True, service_name)
    except Exception as e:
        return (None, service_name)

def Sunrpc_conn(target_host, port, username, password):
    import xmlrpc.client
    service_name="SunRPC"
    try:
        # SunRPC 서버의 주소와 포트
        server_address = f"{target_host}:{port}"

        # XML-RPC 클라이언트 생성
        client = xmlrpc.client.ServerProxy(server_address)

        return (True, service_name)

    except xmlrpc.client.Fault as e:
        #print("SunRPC 에러:", e.faultString)
        return (True, service_name)
    except ConnectionError as e:
        #print("연결 오류:", e)
        return (None, service_name)
    except Exception as e:
        #print("알 수 없는 오류:", e)
        return (None, service_name)
  
def NNTP_conn(target_host, port, username, password):
    import nntplib
    service_name="NNTP"
    server_address = target_host
    try:
        nntp_connection = nntplib.NNTP(server_address)
        return (True, service_name)
    except nntplib.NNTPError as e:
        #print("NNTP 에러:", e)
        return (None, service_name)
    except Exception as e:
        #print("알 수 없는 오류:", e)
        return (None, service_name)
    finally:
        nntp_connection.quit()

def NetBIOS_conn(target_host, port, username, password):
    from impacket import nmb
    service_name="NetBIOS"
    try:
        netbios = nmb.NetBIOS()
        name = netbios.getnetbiosname(target_host)
            
        if name:
            #print(f"IP address: {target_host} to host name : {name}")
            return (True, service_name)
        else:
            #print("Unable to resolve IP address for target.")
            return (None, service_name)
    except Exception as e:
        #print("An error occurred:", e)
        return (None, service_name)

def IMAPS_conn(target_host, port, username, password):
    import imaplib
    service_name="IMAPS"
    try:
        imap_server = imaplib.IMAP4_SSL(target_host)
        imap_server.login(username, password)
        response, _ = imap_server.login(username, password)
        
        if response == 'OK':
            return (True, service_name)
        else:
            #print("Login failed.")
            return (True, service_name)
    except imaplib.IMAP4_SSL.error as ssl_error:
        #print("SSL error:", ssl_error)
        return (None, service_name)
    except imaplib.IMAP4.error as imap_error:
        #print("IMAP error:", imap_error)
        return (None, service_name)
    except Exception as e:
        #print("An unexpected error occurred:", e)
        return (None, service_name)

def IRC_conn(target_host, port, username, password):
    import irc.client
    service_name="IRC"
    class IRCClient(irc.client.SimpleIRCClient):
        def on_welcome(self, connection, event):
            return (True, service_name)
    client = IRCClient()

    try:
        client.connect(target_host, port, username)
        client.start()
        client.connection.disconnect()
        #print("Disconnected to the server.")
        return (True, service_name)
    except irc.client.ServerConnectionError as e:
        print("Error:", e)
        return (None, service_name)

def LDAP_conn(target_host, port, username, password):
    from ldap3 import Server, Connection
    service_name="LDAP"
    server = Server(f'ldap://{target_host}:{port}')
    conn = Connection(server)
    if conn.bind():
        #print("Connected to LDAP server")
        # 연결 종료
        conn.unbind()
        return (True, service_name)
    else:
        #print("Connection failed")
        return (None, service_name)

def SSL_conn(target_host, port, username, password):
    import ssl
    service_name="SSL"
    server_address = (target_host, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_sock = ssl.wrap_socket(sock, ssl_version=ssl.PROTOCOL_TLS)

    try:
        ssl_sock.connect(server_address)

        #print("SSL connection established.")
        return (True, service_name)

    except socket.error as e:
        #print("Error:", e)
        return (None, service_name)

    finally:
        # 연결 종료
        ssl_sock.close()

def SMB_conn(target_host, port, username, password):
    from smbprotocol import exceptions
    import smbclient
    service_name="SMB"

    try:
        smbclient.register_session(target_host, username="username", password="password")
    except exceptions.LogonFailure:
        #print('failed to login')
        return (True, service_name)
    except ValueError:
        #print('no service')
        return (None, service_name)
    else:
        #print('success to login')
        return (True, service_name)

def SMTPS_conn(target_host, port, username, password):
    import smtplib
    service_name="SMTPS"
    try:
        smtp = smtplib.SMTP_SSL(target_host, port)
        smtp.quit()
        return (True, service_name)
    except:
        return (None, service_name)

def LPD_conn(target_host, port, username, password):
    lpd_signature = b'\x02'
    service_name="LPD"

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target_host, port))
        
        sock.settimeout(2) 

        data = sock.recv(1)

        if data == lpd_signature:
            #print("LPD service is identified.")
            return (True, service_name)
        else:
            #print("Not an LPD service.")
            return (None, service_name)

    except Exception as e:
        #print("An error occurred:", str(e))
        return (None, service_name)

    finally:
        sock.close()

def Syslog_conn(target_host, port, username, password):
    facility = 1  # 패시티 (예: user-level messages)
    severity = 3  # 세버리티 (예: Critical)
    message = "This is a test message"

    pri = facility * 8 + severity

    syslog_message = f"<{pri}>{message}"

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        sock.sendto(syslog_message.encode("utf-8"), (target_host, port))
        #print("Syslog 메시지 전송 완료")
    except Exception as e:
        #print(f"전송 중 오류 발생: {e}")
    #finally:
        sock.close()

def NNTPS_conn(target_host, port, username, password):
    import nntplib
    import ssl
    service_name="NNTPS"

    # NNTPS 서버에 연결
    try:
        # Establish a secure connection using SSL
        nntp_connection = nntplib.NNTP_SSL(target_host, port)
        #print("Success!")
        return (True, service_name)
    except nntplib.NNTPError as e:
        #print("NNTPS 에러:", e)
        return (None, service_name)
    except Exception as e:
        #print("알 수 없는 오류:", e)
        return (None, service_name)

def LDAPS_conn(target_host, port, username, password):
    from ldap3 import Server, Connection, ALL
    import ssl
    from ldap3.core.exceptions import LDAPBindError
    service_name="LDAPS"
    try:
        # LDAP 서버 정보 설정
        server = Server(target_host, port=port, use_ssl=True, get_info=ALL)

        # LDAP 서버에 연결
        conn = Connection(server, user=username, password=password, auto_bind=True, auto_referrals=False, client_strategy='SYNC', authentication='SIMPLE')

        if conn.bind():
            #print("Connected to LDAPS server")

            try:
                # TLS 설정 (인증서 유효성 검증을 수행하지 않음)
                conn.start_tls(validate=ssl.CERT_NONE)

                # 연결 종료
                conn.unbind()
                return (True, service_name)
            except Exception as tls_error:
                #print("TLS setup failed:", str(tls_error))
                return (None, service_name)
        else:
            #print("Connection failed")
            return (None, service_name)
    except LDAPBindError as bind_error:
        #print("LDAP Bind failed:", str(bind_error))
        return (True, service_name)
    except Exception as general_error:
        #print("An error occurred:", str(general_error))
        return (None, service_name)

def Kerberos_conn(target_host, port, username, password):
    import requests
    from requests_kerberos import HTTPKerberosAuth, OPTIONAL
    service_name="Kerberos"
    try:
        # Create a session with Kerberos authentication
        session = requests.Session()
        session.verify = False  # Ignore SSL verification for simplicity, consider removing this in production

        auth = HTTPKerberosAuth(mutual_authentication=OPTIONAL)
        response = session.get(f"https://{target_host}:{port}", auth=auth)

        if response.status_code == 200:
            #print("Authenticated successfully")
            return (True, service_name)
        else:
            #print("Authentication failed. Status code:", response.status_code)
            return (True, service_name)
    except Exception as e:
        #print("An error occurred:", e)
        return (None, service_name)

def FTPS_conn(target_host, port, username, password):
    from ftplib import FTP_TLS
    from ftplib import FTP, error_perm
    service_name="FTPS"
    print(service_name)
    try:
        ftps = FTP_TLS()
        ftps.connect(target_host, port)
        ftps.login(username, password)
        #print("FTPS Connection Success")
        ftps.quit()
        return (True, service_name)
    except error_perm as e:
        print(f"FTPS Connection Error: {e}")
        return (None, service_name)
    except Exception as e:
        print(f"FTPS Error: {e}")
        return (None, service_name)

def IMAP_conn(target_host, port, username, password):
    import imaplib
    service_name="IMAP"
    try:
        imap_server = imaplib.IMAP4(target_host)
        imap_server.login(username, password)
        response = imap_server.select()  # Select a mailbox (e.g., "INBOX")
        
        if response[0] == 'OK':
            return (True, service_name)
        else:
            #print("Login failed.")
            return (True, service_name)
    except imaplib.IMAP4.error as imap_error:
        #print("IMAP error:", imap_error)
        return (None, service_name)
    except Exception as e:
        #print("An unexpected error occurred:", e)
        return (None, service_name)

def POP3S_conn(target_host, port, username, password):
    import poplib
    service_name="POP3S"
    try:
        pop3s_connection = poplib.POP3_SSL(target_host, port)
        pop3s_connection.user(username)
        pop3s_connection.pass_(password)
        print("POP3S Connection Success")
        return (True, service_name)
    except poplib.error_proto as e:
        return (True, service_name)
    except Exception as e:
        return (None, service_name)

def MySQL_conn(target_host, port, username, password):
    import mysql.connector
    service_name="MySQL"
    try:
        connection = mysql.connector.connect(
            host=target_host,
            user=username,
            password=password,
            database="mysql"
        )
        if connection.is_connected():
            print("Connected to MySQL")
            connection.close()
            return (True, service_name)
    except mysql.connector.Error as e:
        if e.errno == mysql.connector.errorcode.ER_ACCESS_DENIED_ERROR:
            #print("Authentication error: Invalid credentials")
            return (True, service_name)
        elif e.errno == mysql.connector.errorcode.ER_BAD_DB_ERROR:
            #print("Database not found")
            return (True, service_name)
        else:
            return (None, service_name)

def RDP_conn(target_host, port, username, password):
    import subprocess
    import time
    import pyautogui
    service_name="RDP"
    try:
        # Run the RDP client application (replace with the actual RDP client command)
        rdp_client_cmd = f"mstsc /v:{target_host}"
        subprocess.Popen(rdp_client_cmd, shell=True)

        # Wait for the RDP client to open
        time.sleep(5)

        # Use pyautogui to interact with the RDP client window
        pyautogui.write(username)
        pyautogui.press('tab')
        pyautogui.write(password)
        pyautogui.press('enter')
        if rdp_client_cmd.find("command not")==-1:
            return (None, service_name)
        #print("RDP Connection Success")
        else :
            return (True, service_name)
    except Exception as e:
        #print("RDP Connection Error:", e)
        return (None, service_name)

def PostgreSQL_conn(target_host, port, username, password):
    from psycopg2 import errors
    import psycopg2
    service_name="PostgreSQL"
    try:
        connection = psycopg2.connect(
            host=target_host,
            port=port,
            database="postgres",
            user=username,
            password=password
        )
        if connection:
            #print("Connected to PostgreSQL")
            return (True, service_name)
    except errors.OperationalError as e:
        if e.pgcode == errors.InvalidPassword:
            #print("Invalid password or authentication error")
            return (True, service_name)
        else:
            #print("Operational Error:", e)
            return (None, service_name)

def try_service(target_host, port, username, password, service_func):
    result = service_func(target_host,username, password, port)
    service_status, service_name = result
    print(result)
    return result

def service_scan_service_banner(target_host, open_ports,username, password):

    services_to_try = [
   
    FTP_conn,SSH_conn,SMTP_conn,DNS_conn,HTTP_conn,POP3_conn,NetBIOS_conn,IMAP_conn,SSL_conn,SMB_conn,LPD_conn,
    MySQL_conn, RDP_conn,#(RDP:Only Window)
    PostgreSQL_conn,Daytime_conn,telnet_conn,
    # If want Detected this service, please remove # on the line
    #TFTP_conn, 
    #finger_conn,
    #Sunrpc_conn,
    #NNTP_conn,
    #IRC_conn,
    #LDAP_conn,
    #SMTPS_conn,
    #Syslog_conn,
    #NNTPS_conn,
    #LDAPS_conn,
    #Kerberos_conn,
    #FTPS_conn,
    #IMAPS_conn,
    #POP3S_conn,
    ]

    Detected_service={}
    Closed_service={}
    Not_Detected_service=[]
    banner={}

    
    with tqdm(total=len(open_ports), desc="Scanning Serivces", unit="port") as pbar:
        for port in open_ports:
            pbar.update(1)   
            service_Detected = False
            
            for service_func in services_to_try:
                
                service_status, service_name = service_func(target_host, port, username, password)
                
                if service_status:
                    Detected_service[port] = service_name
                    service_Detected = True
                    break
                elif service_status == "Closed":
                    Closed_service[port] = service_name
                    service_Detected = True
                    break
            
            if service_Detected==False:
                Not_Detected_service.append(port)

    service_result_printing(Detected_service, Closed_service, Not_Detected_service)
    
    with tqdm(total=len(open_ports), desc="Banner Info", unit="port") as pbar:
        for port in open_ports:
            pbar.update(1)
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            banner_info = banner_grabbing(target_host, port, sock)
            if banner_info:
                banner[port] = banner_info
    
    print("Banner Infomation:")
    for port, banner_info in banner.items():
        print(f"Port {port}: {service_name}")
        
def main():
    #just test service scan this codes
    #submit targethost, port, username, password
    #remove # you want to detect service separately
     
    target_host="test.kr"
    port=22
    username = "username"
    password = "password"
    
    #banner_grabbing(target_host, port, sock)
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
    #Sunrpc_conn(target_host, port, username, password) #111
    #NNTP_conn(target_host, port, username, password) #119
    #NetBIOS_conn(target_host, port, username, password) #139
    #IMAP_conn(target_host, port, username, password) #143
    #IRC_conn(target_host, port, username, password) #194, 6667
    #LDAP_conn(target_host, port, username, password)
    #SSL_conn(target_host, port, username, password) #44
    #SMB_conn(target_host, port, username, password) #445 #모듈수정
    #SMTPS_conn(target_host, port, username, password) #465
    #LPD_conn(target_host, port, username, password) #515
    #Syslog_conn(target_host, port, username, password)#514
    #NNTPS_conn(target_host, port, username, password)
    #Message Submission #587 == SMTP 서비스와 동일
    #LDAPS_conn(target_host, port, username, password) #636
    #Kerberos_conn(target_host, port, username, password) #749
    #FTPS_conn(target_host, port, username, password) #990
    #IMAPS_conn(target_host, port, username, password) #903
    #POP3S_conn(target_host, port, username, password) #905
    #MySQL_conn(target_host, port, username, password) # 3306
    #RDP_conn(target_host, port, username, password) #3389
    #PostgreSQL_conn(target_host, port, username, password)#5432
             
if __name__ == "__main__":
    main()




