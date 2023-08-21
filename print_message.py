def print_welcome_message():
    welcome_message = """
    _____                                 ______                                       
    |  __ \                               /  ___|                                       
    | |  \/  __ _  _ __ ___   ____  __ _  \ `--.   ___   __ _  _ __   _ __    ___  _ __ 
    | | __  / _` || '_ ` _ \ |_  / / _` |  `--. \ / __| / _` || '_ \ | '_ \  / _ \| '__|
    | |_\ \| (_| || | | | | | / / | (_| | /\__/ /| (__ | (_| || | | || | | ||  __/| |   
    \____/ \__,_||_| |_| |_|/___| \__,_| \____/  \___| \__,_||_| |_||_| |_| \___||_| 

    Welcome to Gamza Scanner!

    """
    print(welcome_message)


def port_result_printing(thread_ids, filtered_ports, closed_ports, open_ports):
    #print("\nUsed thread IDs:")
    #print(', '.join(map(str, thread_ids)))

    #print(f"\nTotal used thread IDs: {len(thread_ids)}")

    closed_ports.sort()  
    open_ports.sort()   

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


def print_dict(dictionary):
    for key, value in dictionary.items():
        print(f"{key}: {value}")

def service_result_printing(Detected_service, Closed_service, Not_Detected_service):

    print("\nDetected_service:")
    print(Detected_service)

    print("\nClosed_service:")
    print(Closed_service)

    print("\nNot_Detected_service port")
    print(', '.join(map(str, Not_Detected_service)))
    
        
    print(f"\nTotal open services: {len(Detected_service)}")
    print(f"Total closed services: {len(Closed_service)}")
    print(f"Total not detected services: {len(Not_Detected_service)}")
    
    