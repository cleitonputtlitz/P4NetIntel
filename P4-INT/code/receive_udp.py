#!/usr/bin/env python3
import os
import sys
import time

from scapy.all import (
    Ether,
    IP,
    UDP,
    FieldLenField,
    FieldListField,
    IntField,
    IPOption,
    ShortField,
    sniff
)

from intHeaders import int_header, int_trace, int_host, RPC

def handle_pkt(pkt):

    pkt.show2()
    #if RPC in pkt and UDP in pkt and pkt[UDP].dport == 1234:    #so recebe respostas do h2 receive_response_udp sem eBPF
    if RPC in pkt and (UDP in pkt):    #so recebe respostas do h2 receive_response_udp
        #print("got a packet")
        #pkt.show2()
        #sys.stdout.flush()

        rpc_id = pkt[RPC].id

        print("receive_udp rpc_id ", rpc_id)

def main():


    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface = ifaces[0]

    print("sniffing on %s" % iface)
    sys.stdout.flush()

    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))


if __name__ == '__main__':
    main()
