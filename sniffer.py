from scapy.all import *
import json

# Função para processar os pacotes capturados
def process_packet(packet):
    # Aqui você pode adicionar a lógica de processamento dos pacotes capturados
    # Neste exemplo, estamos apenas convertendo o pacote para dicionário e imprimindo

    if TCP in packet:
        packet_info = {
            "source_ip": packet[IP].src,
            "destination_ip": packet[IP].dst,
            "protocol": packet[IP].proto,
            "source_port": packet[TCP].sport if TCP in packet else None,
            "destination_port": packet[TCP].dport if TCP in packet else None,
        }

        # Converter para JSON e salvar em arquivo
        with open("captured_packets.json", "a") as f:
            json.dump(packet_info, f)
            f.write(",\n")  # Nova linha entre os pacotes


# Função para capturar os pacotes de rede
def capture_packets():
    # Definindo a interface de rede para captura
    interface = "Ethernet"  # Substitua "eth0" pela interface de rede correta

    # Iniciando a captura de pacotes
    sniff(iface=interface, prn=process_packet, store=False)

# Executando a captura de pacotes
capture_packets()
