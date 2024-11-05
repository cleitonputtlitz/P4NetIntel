import sys
import subprocess
import argparse

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--load", type=int, required=True)
    parser.add_argument("--size", type=int, default=3)
    return parser.parse_args()

def load_programs(param2):
    print('load_programs')

    #compile
    command = "clang -D COLLECT_SIZE="+str(param2)+" -target bpf -O2 -c ../../eBPF/code/xdp.c -o ../../eBPF/code/xdp.o"
    subprocess.call(command, shell=True)

    command = "clang -D COLLECT_SIZE="+str(param2)+" -target bpf -O2 -c ../../eBPF/code/tc.c -o ../../eBPF/code/tc.o"
    subprocess.call(command, shell=True)

    #create file system
    command = "mount -t bpf bpf /sys/fs/bpf"
    subprocess.call(command, shell=True)

    #attach XDP program
    command = "sudo ip -force link set dev eth0 xdp obj ../../eBPF/code/xdp.o sec xdp"
    subprocess.call(command, shell=True)

    #attach TC program
    command = "sudo tc qdisc add dev eth0 clsact"
    subprocess.call(command, shell=True)

    command = "sudo tc filter add dev eth0 egress bpf da obj ../../eBPF/code/tc.o sec tc"
    subprocess.call(command, shell=True)

def remove_programs():
    print('remove_programs')
    #Detach XDP program
    command = "sudo ip link set dev eth0 xdp off"
    subprocess.call(command, shell=True)

    #Detach TC program
    command = "sudo tc filter del dev eth0 egress"
    subprocess.call(command, shell=True)

    #Detach maps
    command = "rm -r /sys/fs/bpf/ip"
    subprocess.call(command, shell=True)

    command = "rm -r /sys/fs/bpf/tc"
    subprocess.call(command, shell=True)

    command = "rm -r /sys/fs/bpf/xdp"
    subprocess.call(command, shell=True)

def main():

    args = get_args()

    if args.load == 1:
        load_programs(args.size)
    else:
        remove_programs()


if __name__ == '__main__':
    main()
