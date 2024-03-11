#!/bin/bash

function  compilar {
  echo "\nCompilando xdp.c"
  clang -D COLLECT_SIZE=4 -target bpf -O2 -c xdp.c -o xdp.o
  echo "\nCompilando tc.c"
  clang -D COLLECT_SIZE=4 -target bpf -O2 -c tc.c -o tc.o
  echo "\n"
}

function criarDiretorio {
  mount -t bpf bpf /sys/fs/bpf
}

function verLog {
  sudo cat /sys/kernel/debug/tracing/trace_pipe
}

function removerPinMapas {
  echo "\n removerPinMapas\n\n"
  rm -r /sys/fs/bpf/ip
  rm -r /sys/fs/bpf/tc
  rm -r /sys/fs/bpf/xdp
}


function anexarXDP {
  echo " anexarXDP... "
  sudo ip -force link set dev eth0 xdp obj xdp.o sec xdp
}

function anexarTC {
  echo " anexarTC... "
  sudo tc qdisc add dev eth0 clsact
  sudo tc filter add dev eth0 egress bpf da obj tc.o sec tc
}

function desanexarXDP {
  echo " desanexarXDP... "
  sudo ip link set dev eth0 xdp off
}

function desanexarTC {
  echo " desanexarTC... "
  sudo tc filter del dev eth0 egress
}

function consultarProgramas {
  echo " consultando status dos programas... "
  echo " status programa xdp "
  ip link show dev eth0
  echo " status programa tc "
  tc filter show dev eth0 egress
}

action=$1
case $action in
compilar)
  echo " Compilando... "
  compilar
  ;;
anexar)
  criarDiretorio
  anexarXDP
  anexarTC
;;
desanexar)
  desanexarXDP
  desanexarTC
  removerPinMapas
;;
anexarXDP)
  echo " Anexando programa ao hook xdp "
  criarDiretorio
  anexarXDP
  ;;
anexarTC)
  echo " Anexando programa ao hook tc "
  criarDiretorio
  anexarTC
  ;;
desanexarXDP)
    echo " Removendo programa do hook XDP "
    desanexarXDP
    ;;
desanexarTC)
    echo " Removendo programa do hook tc "
    desanexarTC
    ;;
consultarProgramas)
    consultarProgramas
    ;;
*)
  echo "unknown"
  ;;
esac
