# P4NetIntel: End-to-End Network Telemetry with eBPF and XDP


P4NetIntel is a system that tracks the entire life cycle of a flow using end-to-end telemetry. The system extends INT techniques with host telemetry using eBPF, which can monitor application requests without changing the application code. P4NetIntel switches employ techniques to reduce the telemetry overhead, such as discretizing monitoring values and sampling. In addition, eBPF-XDP and TC hooks are used on hosts to intercept and monitor incoming packets transparently to applications.


## Getting started: 

To run P4NetIntel we need to: 

- Compile the P4 program and instantiate to the target (e.g. Mininet).
- run the script eBPF_load.py to compile and attach the eBPF programs to the server

