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
    RandString
)

from intHeaders import *

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

    if len(sys.argv)<4:
        print('pass 3 arguments: <destination> <packets per second> <number message>')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    print("sending on interface %s to %s" % (iface, str(addr)))

    num_packets = int(sys.argv[3])
    packets_per_second = int(sys.argv[2])
    interval = 1.0 / packets_per_second
    payload_size = 1

    #3, 9, 18
    qtd_traces=18

    packets = []
    for x in range(1, num_packets):
        rpc_id = get_rpc_id()
        pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff',type=TYPE_INT_HEADER)

        pkt = pkt / int_header(qtd_traces=qtd_traces)
        for j in range(qtd_traces):
            if(j == qtd_traces-1):
	               pkt = pkt / int_trace(swid=j, next_proto=TYPE_IPV4)
            else:
            	   pkt = pkt / int_trace(swid=j,next_proto=TYPE_INT_TRACE)


        pkt = pkt / IP(dst=addr) / UDP(dport=1234, sport=4321)
        pkt = pkt / RPC(id=rpc_id) / Raw(RandString(size=payload_size))
        #sendp(pkt, loop=0, iface=iface, verbose=False)
        packets.append(pkt)
    pkt.show2()

    for i in range(20):
        start_time = time.time()
        sendp(packets, inter=0.0025, loop=0, iface=iface, verbose=False)
        end_time = time.time()
        print(f"Send {i}. Total time {end_time - start_time}")


if __name__ == '__main__':
    main()
