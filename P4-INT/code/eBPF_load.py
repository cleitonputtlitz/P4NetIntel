import sys
import subprocess

def load_programs(param2):
    print('load_programs')

    #compilar
    command = "clang -D COLLECT_SIZE="+str(param2)+" -target bpf -O2 -c ../../eBPF/code/xdp.c -o ../../eBPF/code/xdp.o"
    subprocess.call(command, shell=True)

    command = "clang -D COLLECT_SIZE="+str(param2)+" -target bpf -O2 -c ../../eBPF/code/tc.c -o ../../eBPF/code/tc.o"
    subprocess.call(command, shell=True)

    #criar file system
    command = "mount -t bpf bpf /sys/fs/bpf"
    subprocess.call(command, shell=True)

    #anexar programa XDP
    command = "sudo ip -force link set dev eth0 xdp obj ../../eBPF/code/xdp.o sec xdp"
    subprocess.call(command, shell=True)

    #anexar programa TC
    command = "sudo tc qdisc add dev eth0 clsact"
    subprocess.call(command, shell=True)

    command = "sudo tc filter add dev eth0 egress bpf da obj ../../eBPF/code/tc.o sec tc"
    subprocess.call(command, shell=True)

def remove_programs():
    print('remove_programs')
    #Desanexar programa XDP
    command = "sudo ip link set dev eth0 xdp off"
    subprocess.call(command, shell=True)

    #Desanexar programa TC
    command = "sudo tc filter del dev eth0 egress"
    subprocess.call(command, shell=True)

    #Desanexar maps
    command = "rm -r /sys/fs/bpf/ip"
    subprocess.call(command, shell=True)

    command = "rm -r /sys/fs/bpf/tc"
    subprocess.call(command, shell=True)

    command = "rm -r /sys/fs/bpf/xdp"
    subprocess.call(command, shell=True)

def main():

    param1 = int(sys.argv[1])
    param2 = int(sys.argv[2])
    

    if param1 == 1:
        load_programs(param2)
    else:
        remove_programs()


if __name__ == '__main__':
    main()
