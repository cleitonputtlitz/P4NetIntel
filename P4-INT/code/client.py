import time
import random
from scapy.all import *
import queue
import threading
from time import sleep
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Timer

from intHeaders import RPC

def get_rpc_id():
    return random.getrandbits(32)

def grv_results(file_name, queue):

    if not os.path.exists(os.path.dirname(file_name)):
        os.makedirs(os.path.dirname(file_name))

    f = open(file_name, "a")
    for _ in range(queue.qsize()):
        packet_info = queue.get_nowait()
        #rpc_id, send_time, receive_time, latencia
        line = f"{packet_info[0]};{packet_info[1]};{packet_info[2]};{packet_info[3]};\n"
        f.write(line)

    f.close()

def udp_request(client_address, server_address):

    request_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    request_socket.bind(('10.0.1.1',0))
    request_socket.setblocking(0)

    rpc_id = get_rpc_id()
    message = bytes(RPC(id=rpc_id) / Raw(RandString(size=100)))

    request_socket.sendto(message, ('10.0.2.2',1234))
    send_time = time.perf_counter_ns()
    received_time = 0

    # select to set timeout of 1 sec
    ready = select.select([request_socket],[],[],1)
    if ready[0]:
        (server_data,(server_ip,server_port)) = request_socket.recvfrom(1024)
        received_time = time.perf_counter_ns()
        latencia = (received_time - send_time) / 1000000
    else:
        print(f"udp_request {rpc_id} no response from server")
        latencia = 0

    request_socket.close()

    return (rpc_id, send_time, received_time, latencia)

def concurrent_request(request_rate, result):

    client_address = ('10.0.1.1', 0)
    server_address = ('10.0.2.2', 1234)
    print(f'send requests {request_rate}')
    workers = 20
    with ThreadPoolExecutor(workers) as executor:
        futures = [executor.submit(udp_request, client_address, server_address) for i in range(request_rate)]

    results = [future.result() for future in futures]

    result.put(results)

    executor.shutdown()

    return 0

def main():
    
    #client_port = 4321
    #client_ip = '10.0.1.1'
    requests = [int(sys.argv[1])]
    #requests = [1000] #[400, 500, 600, 700, 800, 900, 1000, 1100, 1200]
    #request_rate  = 300
    num_testes    = 1
    duration_time = 30
    results = []

    for request_rate in requests:
        average_request = 0

        for test in range(num_testes):
            print(f'\nIniciando teste {test+1} pps: {request_rate}')
            start_time = time.time()

            result = Queue()

            for i in range(duration_time):
                answer = concurrent_request(request_rate, result)
                #sleep(1)


            end_time = time.time()

            # throughput = data/time
            send_data = (100 * request_rate * duration_time)
            throughput = send_data / (end_time - start_time)

            receive_pkt = Queue()
            latencia = 0
            erros = 0
            for _ in range(result.qsize()):
                info = result.get_nowait()
                for i in range(request_rate):
                    if( info[i][3] > 0 ):
                        receive_pkt.put(info[i])
                        latencia += info[i][3]
                    else:
                        erros += 1

            average_request += latencia / receive_pkt.qsize()

            print(f"Duration: {end_time - start_time} env: {receive_pkt.qsize()} rtt: {latencia / receive_pkt.qsize()} erros: {erros} send_data: {send_data} throughput: {throughput}")
            f = open('log.txt', "a")
            line = f"Duration: {end_time - start_time} env: {receive_pkt.qsize()} rtt: {latencia / receive_pkt.qsize()} erros: {erros} send_data {send_data} throughput: {throughput}\n"
            f.write(line)
            f.close()

            grv_results(f"logsExec/{request_rate}/send_ receive.csv",receive_pkt)

        results.append((request_rate, average_request / num_testes ))
        print(f'request_rate: {request_rate} average {average_request / num_testes}')
        f = open('log.txt', "a")
        line = f'request_rate: {request_rate} average {average_request / num_testes} Data/hora: {datetime.now()}\n\n'
        f.write(line)
        f.close()

    print(results)

    os._exit(0)

if __name__ == "__main__":
    main()
