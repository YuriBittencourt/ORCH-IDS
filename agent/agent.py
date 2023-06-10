from pymongo import MongoClient
from dotenv import dotenv_values
from scapy.all import *
from datetime import datetime

config = dotenv_values()

mongo_db = config['MONGO_DB']
client = MongoClient(host=config['MONGO_HOST'], port=int(config['MONGO_PORT']))
db = client[mongo_db]
collection = db[config['MONGO_COLLECTION_QUEUE']]
queue = []

interface = config['NETWORK_INTERFACE']

# IANA protocol codes to names
protocols = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP'
}


def process_packet(packet):

    # We only want IP packets
    if IP not in packet:
        return

    # Ethernet header
    packet_info = {
        "captured_by": get_if_addr(interface),
        "timestamp": int(datetime.now().timestamp() * 1000),
    }

    # Unpack
    packet = packet.payload

    # extract protocol number, IPv6 calls this field as nextHeader, that is why packet.nh
    protocol = packet.proto if packet.version == 4 else packet.nh

    # We only support ICMP, TCP and UDP
    if protocol not in protocols:
        return

    # IPv4/IPv6
    packet_info["source_ip"] = packet.src
    packet_info["destination_ip"] = packet.dst
    packet_info["ip_version"] = packet.version
    packet_info["protocol"] = protocols[protocol]

    # IPv4 has a len attribute, IPv6 has a plen attribute
    packet_info["length"] = packet.len if packet.version == 4 else packet.plen

    # Unpack
    packet = packet.payload

    # Extract ports if there is
    if hasattr(packet, "sport") and hasattr(packet, "dport"):
        packet_info["source_port"] = packet.sport
        packet_info["destination_port"] = packet.dport

    # Extract flags from TCP
    if TCP in packet:
        packet_info["flags"] = [flag for flag in packet.flags]

    # Enqueue and save queue
    queue.append(packet_info)
    save_packet(queue)


def save_packet(queue):
    if len(queue) == 10:
        collection.insert_many(queue)
        queue.clear()


def capture_packets():

    # Iniciando a captura de pacotes
    sniff(iface=interface, prn=process_packet, store=False)


# Executando a captura de pacotes
capture_packets()
