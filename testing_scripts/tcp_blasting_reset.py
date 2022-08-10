#!/usr/bin/python3.10
from scapy.all import *

SRC_PORT = 55586
DST_IP = '10.0.0.4'
DST_PORT = 6668

START_SEQ = random.randint(0, 0xffffffff)
START_ACK = random.randint(0, 0xffffffff)

client_seq = START_SEQ

ip = IP(dst=DST_IP)

#ack
tcp_ack = TCP(sport=SRC_PORT, dport=DST_PORT, flags='A', seq=START_SEQ, ack=START_ACK)

print("\n---------- TCP Ack ----------")

sniffer = AsyncSniffer(filter="src host " + DST_IP + " and tcp src port " + str(DST_PORT), count=1)
sniffer.start()
# Send random ACK to get seq and ack numbers
# ----------- TCP ACK -----------
send(ip/tcp_ack)
# ----------- TCP ACK -----------
filt = "src host " + DST_IP# + " and tcp src port " + str(DST_PORT)
print("Using filter: '" + filt + "'")

sniffer.join()
response_tcp_ack = sniffer.results[0]
print(response_tcp_ack)
print("\n---------- TCP Ack - Done ----------\n")

print("---------- TCP Fin ----------")

# ----------- TCP FIN -----------
tcp_fin = TCP(sport=SRC_PORT, dport=DST_PORT, flags='FA', seq=response_tcp_ack.ack, ack=response_tcp_ack.seq)

response_tcp_fin = sr1(ip/tcp_fin, timeout=5)
print(response_tcp_fin)
client_seq = response_tcp_fin.ack
tcp_ack.seq = client_seq
tcp_ack.ack = response_tcp_fin.seq + 1
send(ip/tcp_ack)
# ----------- TCP FIN -----------

print("---------- TCP Fin - Done ----------")