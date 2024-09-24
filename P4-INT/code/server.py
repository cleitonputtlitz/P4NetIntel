#!/usr/bin/env python3
import os
import sys
import time
from time import sleep
import threading
import socket
from scapy.all import *


def handle_client(server_socket, data, client_address):
    server_socket.sendto(data, client_address)

def main():

    host = '10.0.2.2'
    port = 1234

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((host, port))
    server_socket.settimeout(200)

    print(f"Server listening on {host}:{port}")

    pacotes_recebidos = 0
    try:
        start_time = time.time()
        while True:

            data, client_address = server_socket.recvfrom(1024)
            server_socket.sendto(data, client_address)
            #print(f'pacote recebido de {client_address}')

            pacotes_recebidos += 1
    except Exception as e:
        print(f"Exception in send: {e}")

    finally:
        end_time = time.time()
        print(f'Total de packets received {pacotes_recebidos}, time: {(end_time-start_time)},  pps: {pacotes_recebidos/(end_time-start_time)}')


    os._exit(0)

if __name__ == "__main__":
    main()
