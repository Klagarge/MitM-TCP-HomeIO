# Home IO Packet monitorer

This script is used to monitor the packets from Home IO simulation and modified them.

It uses the `scapy` library to read and modify the packets. Packet are get from the queue created by `iptables`.

This script have to be run on sudo mode on an MitM environment. (e.g. ARP poisoning with `ettercap`)

## Prerequisites

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