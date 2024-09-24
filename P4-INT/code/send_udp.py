#!/usr/bin/env python3
import socket
import sys
from time import sleep
import random
import time

from scapy.all import (
    IP,
    UDP,
    Ether,
    get_if_hwaddr,
    get_if_list,
    sendp,
    Raw,
    RandString,
    conf,
    sendpfast
)

from intHeaders import RPC, TYPE_RPC, TYPE_IPV4

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def get_rpc_id():
    return random.getrandbits(32)

def main():

    if len(sys.argv)<5:
        print('pass 4 arguments: <destination> <packets per second> <total time> <id>')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    tempo_total = int(sys.argv[3])

    payload_size = 100

    #s = conf.L2socket(iface=iface)

    try:
        vetor_pacotes = []
        i=0
        
        while(i<1):
            i+=1
            rpc_id = get_rpc_id()
            pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff',type=TYPE_IPV4)
            pkt = pkt /IP(dst=addr) / UDP(dport=4321, sport=1234)
            pkt = pkt / RPC(id=rpc_id, next_proto=0) / Raw(RandString(size=payload_size))
            vetor_pacotes.append(pkt)

        pkt.show2()

        print("sending on interface %s to %s" % (iface, str(addr)))
        tempo_inicio = time.time()

        sendpfast(vetor_pacotes, pps=400, loop=1, iface=iface, file_cache=True)

        tempo_fim = time.time()
        tempo_total = (tempo_fim - tempo_inicio)
        print(f'tempo_inicio {tempo_inicio} tempo_fim {tempo_fim} tempo_total (s) {tempo_total}')
        print(f'fim envio pacotes... Enviados {i}')

    except KeyboardInterrupt:
        raise

    finally:

        sleep(10)

if __name__ == '__main__':
    main()
