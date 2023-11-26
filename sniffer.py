import socket
import struct
import binascii
import netifaces
import time
import sys
import os
import subprocess

# Definir constantes
ICMP_THRESHOLD = 100  # Número de pacotes ICMP para acionar um aviso
ARP_THRESHOLD = 5     # Número de pacotes ARP Spoofing para acionar um aviso
TIME_INTERVAL = 10    # Intervalo de tempo em segundos para contagem dos pacotes

# Inicializar variáveis
arp_table = {}  # Tabela para monitorar pacotes ARP
icmp_table = {} # Tabela para monitorar pacotes ICMP
start_time = time.time()
info_time = time.time()

# Contadores de pacotes
arp_request_count = 0
arp_reply_count = 0
ipv4_count = 0
icmp_count = 0
ipv6_count = 0
icmpv6_count = 0
udp_count = 0
tcp_count = 0


# Códigos ANSI para cores no terminal
class bcolors:
    WARNING = '\033[91m'

# função para ver algumas coisa estranhas na minha rede
# a tabela arp estav pegando um ip do gateway default com um mac de outra subrede
# tal ip e mac enviavam muitos arps replay (sem testar ataque nenhum)
# isso caia direto no verificação de arp spoof
# agora não sei se é só na minha rede por ter dois roteadores e 1 atuando como repetidor ou vai acontecer em outras redes
def gateway_default_and_mac():
    try:
        # No Linux, o gateway padrão geralmente está na posição 2 da saída do comando 'ip route'
        gateways = netifaces.gateways()
        default_gateway = gateways['default'][netifaces.AF_INET][0]

        #Pega mac estranho que aparece na tabela
        interface = gateways['default'][netifaces.AF_INET][1]
        mac_address = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']

        print (default_gateway)
        print (mac_address) # traz uma mac de outra subrede
        
        # Dessa foram pega o ip e mac corretos 
        gateway2 = os.popen("ip route | awk '/default/ { print $3 }'").read().strip()
        result = subprocess.check_output(["arp", "-a"]).decode("utf-8")
        lines = result.split('\n')
        
        mac_address2 = ""
        for line in lines:
            if gateway2 in line:
                mac_address2 = line.split(' ')[3]

        print (gateway2)
        print (mac_address2)

        return default_gateway, mac_address
    except Exception as e:
        print(f"Erro ao obter o gateway padrão: {e}")
        return None, None


default_gateway, mac_address = gateway_default_and_mac()


# Sniffer ==============================================================================================

# Função para analisar pacotes Ethernet
def parse_ethernet_header(data):
    # Desempacotar os primeiros 14 bytes do pacote Ethernet
    eth_header = struct.unpack('!6s6sH', data[:14])
    # Extrair o endereço MAC de destino e converter para formato legível
    dest_mac = binascii.hexlify(eth_header[0]).decode('utf-8')
    # Extrair o endereço MAC de origem e converter para formato legível
    src_mac = binascii.hexlify(eth_header[1]).decode('utf-8')
    # Extrair o tipo de protocolo da camada de rede e converter para o formato correto
    proto = eth_header[2]
    # Retornar as informações extraídas e os dados restantes do pacote
    return dest_mac, src_mac, proto, data[14:]

def parse_arp_packet(data):
    global arp_table, arp_request_count, arp_reply_count

    arp_header = struct.unpack('!HHBBH6s4s6s4s', data[:28])
    hardware_type = arp_header[0]
    protocol_type = arp_header[1]
    hardware_size = arp_header[2]
    protocol_size = arp_header[3]
    opcode = arp_header[4]
    sender_mac = ':'.join(f"{byte:02x}" for byte in arp_header[5])
    sender_ip = socket.inet_ntoa(arp_header[6])
    target_mac = ':'.join(f"{byte:02x}" for byte in arp_header[7])
    target_ip = socket.inet_ntoa(arp_header[8])

    # Usando uma tupla como chave
    key = (sender_ip, sender_mac)

    # Verificando se a tupla já existe no dicionário
    if key in arp_table:
        if opcode == 1:  # ARP Request
            arp_table[key]['request_count'] += 1
            arp_request_count +=1

        if opcode == 2:  # ARP Reply
            arp_table[key]['replay_count'] += 1
            arp_reply_count +=1

            # # Verificar se o número de pacotes de replays excede o limite
            # if arp_table[key]['replay_count'] > arp_table[key]['request_count'] and arp_table[key]['replay_count'] >= ARP_THRESHOLD:
            #     print(f"{bcolors.WARNING}Ataque ARP Spoofing detectado! {arp_table[key]['replay_count']} pacotes ARP Spoofing em {(time.time() - start_time)} segundos.{bcolors.WARNING}")
            #     reset()
       
    else:
        # Adicionar uma nova entrada ao dicionário
        if opcode == 1:  # ARP Request
            arp_table[key] = {'request_count': 1, 'replay_count': 0}
            arp_request_count +=1
        if opcode == 2:  # ARP Reply
            arp_table[key] = {'request_count': 0, 'replay_count': 1}
            arp_reply_count +=1


# Função para analisar pacotes IP
def parse_ip_packet(data):
    # Desempacotar os primeiros 20 bytes do pacote IP
    ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])

    # Obter o campo "version_ihl" e extrair a versão e o comprimento do cabeçalho
    version_ihl = ip_header[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF

    # Extrair informações do cabeçalho IP
    ttl = ip_header[5]  # Tempo de vida (TTL)
    protocol = ip_header[6]  # Protocolo de transporte
    src_ip = socket.inet_ntoa(ip_header[8])  # Endereço IP de origem
    dest_ip = socket.inet_ntoa(ip_header[9])  # Endereço IP de destino

    # Retornar informações extraídas e os dados restantes do pacote após o cabeçalho IP
    return version, ihl, ttl, protocol, src_ip, dest_ip, data[ihl * 4:]

# Função para analisar pacotes ICMP
def parse_icmp_packet(data, src_ip):
    global icmp_table

    icmp_header = struct.unpack('!BBHHH', data[:8])
    icmp_type = icmp_header[0]

    if icmp_type == 8:  # ICMP Echo Request
        # Verificar se é do mesmo endereço/maquina
        if src_ip in icmp_table:
            icmp_table[src_ip]+= 1

            # # Verificar se o número de pacotes de requests excede o limite
            # if icmp_table[src_ip] >= ICMP_THRESHOLD:
            #     print(f"{bcolors.WARNING}Ataque ICMP Flooding detectado! {icmp_table[src_ip]} pacotes ICMP em {(time.time() - start_time)} segundos.{bcolors.WARNING}")
            #     reset()
        else:
            # Se não for do mesmo endereço, adiciona à tabela
            icmp_table[src_ip] = 1

def reset():
    global icmp_table, arp_table, start_time
    # Reiniciar as variáveis para o próximo intervalo de tempo
    arp_table = {}  # Tabela para monitorar pacotes ARP
    icmp_table = {} # Tabela para monitorar pacotes ICMP
    start_time = time.time()


def print_info():
    # Imprimir estatísticas ao final
        print(f"\nEstatísticas:")
        print(f"Nível de Enlace:")
        print(f"Quantidade de pacotes ARP Request: {arp_request_count}")
        print(f"Quantidade de pacotes ARP Reply: {arp_reply_count}")
        print(f"Nível de Rede:")
        print(f"  Quantidade de pacotes IPv4: {ipv4_count}")
        print(f"  Quantidade de pacotes ICMP: {icmp_count}")
        print(f"  Quantidade de pacotes IPv6: {ipv6_count}")
        print(f"  Quantidade de pacotes ICMPv6: {icmpv6_count}")
        print(f"Nível de Transporte:")
        print(f"  Quantidade de pacotes UDP: {udp_count}")
        print(f"  Quantidade de pacotes TCP: {tcp_count}")

# Função principal para capturar e analisar pacotes TCP
def sniffer():
    global ipv4_count, icmp_count, ipv6_count, icmpv6_count, udp_count, tcp_count, info_time
    # O uso de socket.AF_PACKET com socket.SOCK_RAW e socket.ntohs(3) é apropriado quando se deseja trabalhar
    # com pacotes de rede brutos na camada de enlace, incluindo informações além do nível de transporte (como TCP ou UDP). 
    # Essa abordagem é comumente utilizada para a construção de ferramentas de análise de rede de baixo nível, como sniffers.
    # Por outro lado, socket.AF_INET com socket.SOCK_STREAM é a escolha típica para comunicação de rede no nível de transporte, 
    # especificamente para TCP/IP.
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    try:
        # Loop infinito para receber e analisar pacotes continuamente
        while True:
            # Receber um pacote cru e informações sobre o remetente (endereço)
            # A escolha do valor 65536 como tamanho máximo do pacote(65536) é comum e está relacionada com 
            # o tamanho máximo teórico de um pacote Ethernet padrão. estamos garantindo que o programa é 
            # capaz de lidar com o tamanho máximo possível de um pacote Ethernet.
            raw_data, addr = conn.recvfrom(65536)

            # Chamar a função para analisar o cabeçalho Ethernet e obter informações importantes
            dest_mac, src_mac, eth_proto, data = parse_ethernet_header(raw_data)

            # Verificar se o pacote é do tipo ARP
            if eth_proto == 0x0806:  # ARP
                parse_arp_packet(data)

            # Verificar se o pacote é do tipo IPv4
            if eth_proto == 0x0800:

                ipv4_count +=1

                # Chamar a função para analisar o cabeçalho IP e obter informações
                version, ihl, ttl, protocol, src_ip, dest_ip, transport_data = parse_ip_packet(data)

                if protocol == 1:
                    icmp_count +=1
                    parse_icmp_packet(transport_data, src_ip)
                
                if protocol == 6:
                    tcp_count  +=1

                if protocol == 17:
                    udp_count += 1

            # Verificar se o pacote é do tipo IPv6
            if eth_proto == 0x86DD:

                ipv6_count +=1

                # Chamar a função para analisar o cabeçalho IP e obter informações
                version, ihl, ttl, protocol, src_ip, dest_ip, transport_data = parse_ip_packet(data)

                # Verificar se o pacote é do tipo ICMP
                if protocol == 58:  # ICMPv6 tem número de protocolo 58
                    icmpv6_count +=1

                if protocol == 6:
                    tcp_count  +=1

                if protocol == 17:
                    udp_count += 1
                    
                       
            # A verificação de ataques vai se dar só a cada TIME_INTERVAL
            # Isso ajuda a evitar falsos positivos que podem ocorrer durante a inicialização da rede.
            # Verificar se o intervalo de tempo definido foi atingido
            if time.time() - start_time >= TIME_INTERVAL:

                # Verificar se tem um endereço na tabela de icmp que o número de pacotes de requests excede o limite
                for ip, count in icmp_table.items():
                    if count >= ICMP_THRESHOLD:
                        # Aqui podemos implementar a lógica para gerar um aviso ou realizar outras ações.
                        print(f"{bcolors.WARNING}Ataque ICMP Flooding detectado! {count} pacotes ICMP em {TIME_INTERVAL} segundos.{bcolors.WARNING}")

                # Verificar se tem um endereço na tabela de arp que o número de pacotes de replay excede o limite
                for key, count in arp_table.items():

                    # Tdm um mac de outra subrede mas com o mesmo ip fazendo varios arpreplay 
                    # Essa verifica ção evida detectar logo de cara mas é muito estranho
                    # não sei se isso é da minha rede ou vai acontecer em outras
                    if key[1] != mac_address: #verificação devido a uma estranhesa da redde 
                        if arp_table[key]['replay_count'] > arp_table[key]['request_count'] and arp_table[key]['replay_count'] >= ARP_THRESHOLD:
                            # Aqui podemos implementar a lógica para gerar um aviso ou realizar outras ações.
                            print(f"{bcolors.WARNING}Ataque ARP Spoofing detectado! {arp_table[key]['replay_count']} pacotes ARP Spoofing em {TIME_INTERVAL} segundos.{bcolors.WARNING}")

                print_info()

                # Imprimir a tabela ARP
                print("Tabela ARP:")
                for entry, counts in arp_table.items():
                    print(f"{entry}: Request Count = {counts['request_count']}, Replay Count = {counts['replay_count']}")
                
                # sys.exit(1)
                # info_time = time.time()
                reset()
                

    except KeyboardInterrupt:
            print("Sniffer encerrado.")



if __name__ == "__main__":
    # Iniciar o sniffer para pacotes TCP
    sniffer()
