#!/usr/bin/env python3
import os
import sys
import time
from time import sleep
import threading
import struct

import socket
from scapy.all import *

from intHeaders import *

def gravar_resultados(file_name, queue):

    print(file_name)
    if not os.path.exists(os.path.dirname(file_name)):
        os.makedirs(os.path.dirname(file_name))

    while(True):
        f = open(file_name, "a")

        packet_info = queue.get(block=True, timeout=60)

        packet = Ether(packet_info)
        #packet.show2()
        if Ether in packet and packet[Ether].type==TYPE_INT_HEADER:
            pkt_size = 0

            if int_header in packet:
                int_header_h = packet[int_header]
                pkt_size += len(int_header_h)

            if IP in packet:
                IP_h = packet[IP]
                pkt_size -= len(IP_h)

            if(pkt_size < 0):
                pkt_size = 0

            line = str(pkt_size) + ";\n"
            f.write(line)

        f.close()

def main():

    host = '10.0.4.4'
    port = 4321
    iface = 'eth0'

    file_name = sys.argv[1]

    receive_pkt = Queue()

    #server_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW)
    #socket.ntohs(0x0003) to capture all protocolls
    server_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    server_socket.bind((iface, 0))
    server_socket.settimeout(60)

    print(f"Monitor Listening on {host}:{port}")

    # Thread para gerar os pacotes
    thread_gravar = threading.Thread(target=gravar_resultados, args=(file_name, receive_pkt,))
    thread_gravar.start()
    
    pkt_recebidos = 0
    packet = ''
    try:
        while True:
            # Recebe dados do cliente
            data, client_address = server_socket.recvfrom(4096)
            pkt_recebidos += 1
            receive_pkt.put(data)

    except Exception as e:
        print(f"Exception: {e}")
    finally:
        
        f = open("logsExec/log.txt", "a")
        line = f"MONITOR: recv {pkt_recebidos}\n"
        f.write(line)
        f.close()

        thread_gravar.join()
        #gravar_resultados(f"logsExec/{300}/pkt_size.csv",receive_pkt)

    os._exit(0)


if __name__ == "__main__":
    main()
