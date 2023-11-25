import socket
import struct
import binascii
import time
import sys

# Definir constantes
ICMP_THRESHOLD = 100  # Número de pacotes ICMP para acionar um aviso
ARP_THRESHOLD = 3     # Número de pacotes ARP Spoofing para acionar um aviso
TIME_INTERVAL = 10    # Intervalo de tempo em segundos para contagem dos pacotes

# Inicializar variáveis
arp_cache = {}
arp_table = {}  # Tabela para monitorar pacotes ARP
icmp_table = {} # Tabela para monitorar pacotes ICMP
start_time = time.time()


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
    global arp_table

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
        if opcode == 2:  # ARP Reply
            arp_table[key]['replay_count'] += 1
            # Verificar se o número de pacotes de requests excede o limite
            if arp_table[key]['replay_count'] < arp_table[key]['request_count'] and arp_table[key]['replay_count'] >= ARP_THRESHOLD:
                print(f"Ataque ARP Spoofing detectado! {arp_table[key]['replay_count']} pacotes ARP Spoofing em {(time.time() - start_time)} segundos.")
       
    else:
        # Adicionar uma nova entrada ao dicionário
        if opcode == 1:  # ARP Request
            arp_table[key] = {'request_count': 1, 'replay_count': 0}
        if opcode == 2:  # ARP Reply
            arp_table[key] = {'request_count': 0, 'replay_count': 1}

    if opcode == 1:  # ARP Request
        # Verificar se é do mesmo endereço/maquina
        if key in arp_table:
            arp_table[key]['request_count'] += 1
        else:
            # Se não for do mesmo endereço, adiciona à tabela
            arp_table[key] = {'request_count': 1, 'replay_count': 0}
    elif opcode == 2:  # ARP Reply
        # Incrementar o contador de replay
        if key in arp_table:
            arp_table[key]['replay_count'] += 1
        else:
            # Ponto de estranheza
            # Se não for do mesmo endereço, adiciona à tabela
            arp_table[key] = {'request_count': 0, 'replay_count': 1}


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
            # Verificar se o número de pacotes de requests excede o limite
            if icmp_table[src_ip] >= ICMP_THRESHOLD:
                 print(f"Ataque ICMP Flooding detectado! {src_ip} pacotes ICMP em {(time.time() - start_time)} segundos.")
        else:
            # Se não for do mesmo endereço, adiciona à tabela
            icmp_table[src_ip] = 1

# Função principal para capturar e analisar pacotes TCP
def sniffer():
    global icmp_table, arp_table, start_time

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

            # tabela de monitoramento - cache para todos os pacotes passados na rede
            # ip request - ip replay ok
            # nada       - ip replay estranho (ja começa o monitoramento com mais acerto)
            if eth_proto == 0x0806:  # ARP
                parse_arp_packet(data)

               

            # Verificar se o pacote é do tipo IPv4
            if eth_proto == 0x0800:
                # Chamar a função para analisar o cabeçalho IP e obter informações
                version, ihl, ttl, protocol, src_ip, dest_ip, transport_data = parse_ip_packet(data)

                # Verificar se o pacote é do tipo ICMP
                # Abrir para ver opcode request e replay - como no arp
                # incrementar só se o request for do mesmo endereço/maquina
                if protocol == 1:
                    # print(f"Pacote ICMP detectado de {src_ip} para {dest_ip}")
                    parse_icmp_packet(transport_data, src_ip)
                    
            # Verificar se o intervalo de tempo definido foi atingido
            if time.time() - start_time >= TIME_INTERVAL:

                # Verificar se tem um endereço na tabela de icmp que o número de pacotes de requests excede o limite
                for ip, count in icmp_table.items():
                    if count >= ICMP_THRESHOLD:
                        # Aqui podemos implementar a lógica para gerar um aviso ou realizar outras ações.
                        print(f"Ataque ICMP Flooding detectado! {count} pacotes ICMP em {TIME_INTERVAL} segundos.")
                        #sys.exit(1)


                # Verificar se o número de pacotes ARP Spoofing excede o limite
                if arp_packet_count >= ARP_THRESHOLD:
                    # Aqui podemos implementar a lógica para gerar um aviso ou realizar outras ações.
                    print(f"Ataque ARP Spoofing detectado! {arp_packet_count} pacotes ARP Spoofing em {TIME_INTERVAL} segundos.")
                    #sys.exit(1)

                # Reiniciar as variáveis para o próximo intervalo de tempo
                arp_table = {}  # Tabela para monitorar pacotes ARP
                icmp_table = {} # Tabela para monitorar pacotes ICMP
                start_time = time.time()
    except KeyboardInterrupt:
            print("Sniffer encerrado.")



if __name__ == "__main__":
    # Iniciar o sniffer para pacotes TCP
    sniffer()
