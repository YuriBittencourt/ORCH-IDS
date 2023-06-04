from pymongo import MongoClient
from dotenv import load_dotenv
from scapy.all import *
import time

load_dotenv()

mongo_host = os.getenv('MONGO_HOST')
mongo_port = int(os.getenv('MONGO_PORT'))
mongo_db = os.getenv('MONGO_DB')
collection = os.getenv('MONGO_COLLECTION_QUEUE')
client = MongoClient(host=mongo_host, port=mongo_port)


db = client[mongo_db]
queue = []


def process_packet(packet):
    #print(packet.show())

    if ARP in packet:
        return

    # Ethernet header
    packet_info = {
        "timestamp": time.time(),
        "source_mac": packet.src,
        "destination_mac": packet.dst,
    }

    packet = packet.payload

    # IPv4/IPv6
    packet_info["source_ip"] = packet.src
    packet_info["destination_ip"] = packet.dst
    packet_info["version"] = packet.version

    # IPv4 has a len attribute, IPv6 has a plen attribute
    packet_info["length"] = packet.len if packet.version == 4 else packet.plen

    if packet.version == 6:
        packet_info["protocol"] = packet.nh

    packet = packet.payload

    # UDP/TCP/ICMP
    if "protocol" not in packet_info:
        packet_info["protocol"] = packet.name

    if hasattr(packet, "sport") and hasattr(packet, "dport"):
        packet_info["source_port"] = packet.sport
        packet_info["destination_port"] = packet.dport

    if TCP in packet:
        packet_info["flags"] = [flag for flag in packet.flags]

    queue.append(packet_info)
    save_packet(queue)


def save_packet(queue):
    if len(queue) == 10:
        db[collection].insert_many(queue)
        queue.clear()


def capture_packets():

    interface = os.getenv('NETWORK_INTERFACE')

    # Iniciando a captura de pacotes
    sniff(iface=interface, prn=process_packet, store=False)


# Executando a captura de pacotes
capture_packets()
