# P4NetIntel: End-to-End Network Telemetry with eBPF and XDP


P4NetIntel is a system that tracks the entire life cycle of a flow using end-to-end telemetry. The system extends INT techniques with host telemetry using eBPF, which can monitor application requests without changing the application code. P4NetIntel switches employ techniques to reduce the telemetry overhead, such as discretizing monitoring values and sampling. In addition, eBPF-XDP and TC hooks are used on hosts to intercept and monitor incoming packets transparently to applications.


## Getting started: 

The P4NetIntel must be run using the tutorial P4 VM. To run it, follow the following steps:


1. Compile the P4 code `INT.p4` and start Mininet:
```bash
cd P4-INT/code
make
```

2. Open two terminals for `h1` and `h2`:
```bash
mininet> xterm h1 h2
```

3. In h2's XTerm, compile and attach the eBPF programs:
```bash
python3 eBPF_load.py 1 3
```

4. In h2's XTerm, start the server:
```bash
python3 server.py
```

5. In h1's XTerm, send 400 packets per second to `h2` using client.py:
```bash
python3 client.py 400
```

6. To see the collected data, start a new terminal for `h4` and run the monitor.py:
```bash
mininet> xterm h4
python3 monitor.py
```

7. To automate the steps 2-5, you can run:
```bash
mininet> source P4NetView.sh
```

8. To detach the eBPF programs, run in h2's XTerm:
```bash
python3 eBPF_load.py 2 0
```


## Repo Organization
```
  ┣ P4-Int/code: P4 code for BMv2
  ┣ P4-Int/code/eBPF_load.py: script to attach eBPF programs on BMv2
  ┣ P4-Int/code/P4NetView.py: a set of example experiments
  ┣ P4-Int/Utils: third party software
  ┣ eBPF/Code: eBPF code for both BMv2 and the real hardware
  ┣ microbenchmark: programs used to test performance on Hardware
```
