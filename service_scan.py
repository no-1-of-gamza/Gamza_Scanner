import socket
Service = {}

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