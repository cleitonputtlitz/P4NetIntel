h2 xterm -e "python3 eBPF_load.py 1 4"
sh echo “Attaching the eBPF programs” &
sh sleep 2

h2 xterm -e "python3 server.py"&

sh sleep 10
h1 xterm -e 'python3 client.py 400'

sh echo “Removing eBPF programs”
h2 xterm -e "python3 eBPF_load.py 2 0"
