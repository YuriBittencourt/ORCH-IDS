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

    # IPv4/IPv6
    packet_info["source_ip"] = packet.src
    packet_info["destination_ip"] = packet.dst
    packet_info["ip_version"] = packet.version

    # IPv4 has a len attribute, IPv6 has a plen attribute
    packet_info["length"] = packet.len if packet.version == 4 else packet.plen

    if packet.version == 6:
        packet_info["protocol"] = packet.nh

    # Unpack
    packet = packet.payload

    # UDP/TCP/ICMP
    if "protocol" not in packet_info:
        packet_info["protocol"] = packet.name

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
