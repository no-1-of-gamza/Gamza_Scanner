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
    print(welcome_message)


def port_result_printing(thread_ids, filtered_ports, closed_ports, open_ports):
    print("\nUsed thread IDs:")
    print(', '.join(map(str, thread_ids)))

    print(f"\nTotal used thread IDs: {len(thread_ids)}")

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
    
    