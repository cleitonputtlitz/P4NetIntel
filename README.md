# P4NetIntel: End-to-End Network Telemetry with eBPF and XDP


P4NetIntel is a system that tracks the entire life cycle of a flow using end-to-end telemetry. The system extends INT techniques with host telemetry using eBPF, which can monitor application requests without changing the application code. P4NetIntel switches employ techniques to reduce the telemetry overhead, such as discretizing monitoring values and sampling. In addition, eBPF-XDP and TC hooks are used on hosts to intercept and monitor incoming packets transparently to applications.


## Getting started: 

To run P4NetIntel we need to: 

- Compile the P4 program and instantiate to the target (e.g. Mininet).
- run the script eBPF_load.py to compile and attach the eBPF programs to the server


## Repo Organization
```
  ┣ P4-Int/code: P4 code for BMv2
  ┣ P4-Int/code/eBPF_load.py: script to attach eBPF programs on BMv2
  ┣ P4-Int/code/P4NetView.py: a set of example experiments
  ┣ P4-Int/Utils: third party software
  ┣ eBPF/Code: eBPF code for both BMv2 and the real hardware
  ┣ microbenchmark: programs used to test performance on Hardware
```
