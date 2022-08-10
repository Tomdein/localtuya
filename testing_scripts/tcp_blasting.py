#!/usr/bin/python3.10
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from requests import session
from scapy.all import *
import hmac

def to_hexstream(bytestream):
    return "{}".format(''.join(format(x, '02x') for x in bytestream))

SRC_PORT = 55586
DST_IP = '10.0.0.4'
DST_PORT = 6668

# START_SEQ = 2000
START_SEQ = random.randint(0, 0xffffffff)

client_seq = START_SEQ
# ip_header_identification = random.randint(0, 65536)

ip = IP(dst=DST_IP)

#syn
tcp_syn = TCP(sport=SRC_PORT, dport=DST_PORT, flags='S', seq=client_seq)

#ack
tcp_ack = TCP(sport=SRC_PORT, dport=DST_PORT, flags='A')

print("\n---------- TCP Syn ----------")
# ----------- TCP SYN -----------
response_tcp_syn = sr1(ip/tcp_syn, timeout=5)
client_seq = response_tcp_syn.ack
# ip_header_identification += 1
# ip.id = ip_header_identification

tcp_ack.seq = client_seq
tcp_ack.ack = response_tcp_syn.seq + 1

send(ip/tcp_ack)
# ----------- TCP SYN -----------
print("---------- TCP Syn - Connected ----------\n")

time.sleep(1)

print("---------- Sending key ----------")
# ----------- TCP DATA -----------
tcp_data = TCP(sport=SRC_PORT, dport=DST_PORT, flags='PA', seq = client_seq, ack = tcp_ack.ack)

# data1 = b'\x00\x00U\xaa\x00\x00\x00\x00\x00\x00\x00\t\x00\x00\x00\'3.4\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xcfd&\x8e\xf6\xb1\x86\xbf\x99\x8e8_("\x0e\xea>w\n\xc2\x00\x00\xaaU'
# load1 = Raw(load=data1)

# send(ip/tcp_data/load1)
# ----------- TCP DATA -----------

# ----------- SEND LOCAL_KEY -----------
prefix = b'\x00\x00U\xaa'
local_seq_n = b'\x00\x00\x00\x00'
local_seq_n = b'\x00\x00\x2f\x45' # 12101 used by my phone
command = b'\x00\x00\x00\x03'
len = b'\x00\x00\x00D'
suffix = b'\x00\x00\xaaU'

local_key = bytearray(get_random_bytes(16))
device_key = b'3f459282e979b65c'
cipher_ECB_AES128 = AES.new(device_key, AES.MODE_ECB)

# padd the message:
    #   const padding=0x10-(payload.length & 0xf)
    #   let buf34 = Buffer.alloc((payload.length + padding), padding)
local_key_encrypted = cipher_ECB_AES128.encrypt(local_key + bytearray(b'\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'))

tuya_packet = bytearray()
tuya_packet += prefix + local_seq_n + command + len + local_key_encrypted
# tuya_packet = bytearray(bytes.fromhex("000055aa00002f45000000030000004428ca3d6e6d2431a5baafc2e22b87b230f41b7d5e6be18fda638ce821456440d9"))

# checksum_sha256 = SHA256.new(data=tuya_packet).digest()
checksum_sha256 = hmac.new(device_key, msg=tuya_packet, digestmod="sha256").digest()

tuya_packet += checksum_sha256 + suffix

print("\nUsing device_key: {},\nSending packet with generated local_key: b'{}',\nencrypted_local_key: b'{}'"
.format(device_key, to_hexstream(local_key), to_hexstream(local_key_encrypted)))

load2 = Raw(load=tuya_packet)
key_resp = sr1(ip/tcp_data/load2, timeout=5)

print("---------- Sending key - Done ----------")
# ----------- SEND LOCAL_KEY -----------

# ----------- PROCESS REMOTE_KEY -----------
# print(ls(key_resp))
tuya_packet = key_resp.load
print(tuya_packet)

prefix          = tuya_packet[0:4]
# Header data
remote_seq_n    = tuya_packet[4:8]
remote_command  = tuya_packet[8:12]
payload_length  = tuya_packet[12:16]

# Payload
payload         = tuya_packet[16:16 + int.from_bytes(payload_length, "big")]
data    = payload[0:-0x24] # Remove 32B hash and 4B suffix
hash    = payload[-0x24:-0x04]
suffix  = payload[-0x04:]

# Some magic I do not understand why (@https://github.com/harryzz/tuyapi/blob/master/lib/message-parser.js, line 149)
# Something about stripping return value.
# Return values are only from devices (remote in my terminology)
if not (int.from_bytes(data[:4], "big") & 0xFFFFFF00):
    data = data[4:]

if int.from_bytes(remote_command, "big") == 0x04: # RENAME_GW (0x04)
    # Calculate hash of tuya packet and compare to hash in message
    calculated_tuya_packet_hash = hmac.new(device_key, msg=tuya_packet[0:-0x24], digestmod="sha256").digest()

    if hash != calculated_tuya_packet_hash:
        print("Hash: {}".format(hash))
        print("Calculated hash: {}".format(calculated_tuya_packet_hash))
        raise Exception("Tuya packet hash does not match with calculated value")

    # Get remote_key
    data = cipher_ECB_AES128.decrypt(data)
    # Remove Padding. 
    # Padding bytes are the length of padding (0x........10101010101010101010101010101010 - padding is 0x10 == 16 and is 16B long)
    # As to my understanding from the code I am rewriting, the padding is always there. Not shure it is true all the time.
    data = data[:-data[-1]] 
    remote_key = data[:0x10] # first 16B is the remote_key

    # Check remote hash of local_key
    remote_hash_of_local_key = data[0x10:0x30] # first 16B is the remote_key
    calculated_hash_of_local_key = hmac.new(device_key, msg=local_key, digestmod="sha256").digest()

    if remote_hash_of_local_key != calculated_hash_of_local_key:
        raise Exception("Local and remote hash of 'local_key' does not match!")

    # Calculate session_key
    session_key = bytearray()
    for i in range(0x00, 0x10):
        session_key.append(local_key[i] ^ remote_key[i])
    session_key = cipher_ECB_AES128.encrypt(session_key)

    # Send response command RENAME_DEVICE(0x05)
    local_seq_n = (int.from_bytes(local_seq_n, byteorder="big") + 1).to_bytes(length=4, byteorder="big")
    command = b'\x00\x00\x00\x05'
    len = b'\x00\x00\x00T' # 32B hashed remote_key + 16B padding + 32B hash + 4B suffix

    remote_key_hashed = bytearray(hmac.new(device_key, msg=remote_key, digestmod="sha256").digest())
    remote_key_hashed_encrypted = cipher_ECB_AES128.encrypt(remote_key_hashed + bytearray(b'\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'))

    tuya_packet = bytearray()
    tuya_packet += prefix + local_seq_n + command + len + remote_key_hashed_encrypted

    checksum_sha256 = SHA256.new(data=tuya_packet).digest()
    checksum_sha256 = hmac.new(device_key, msg=tuya_packet, digestmod="sha256").digest()

    tuya_packet += checksum_sha256 + suffix

    load3 = Raw(load=tuya_packet)

    tcp_data.ack = key_resp.seq + key_resp.len - 40 # Length of IP + TCP + TUYA - IP header length
    tcp_data.seq = key_resp.ack
    send(ip/tcp_data/load3)

    
    print("\n\ndevice_key: '{}',\nlocal_key: '{}',\nremote_key: '{}',\nsession_key: '{}'\n\n"
    .format(to_hexstream(device_key), to_hexstream(local_key), to_hexstream(remote_key), to_hexstream(session_key)))

    print()
else:
    raise Exception("Expected 'RENAME_GW (0x04)' command")
print("---------- PROCESS REMOTE_KEY - Done ----------")
# ----------- PROCESS REMOTE_KEY -----------

# ----------- TCP Keep-Alive -----------
# tcp_ack.seq = client_seq-1 # TCP Keep-Alive ACK
# send(ip/tcp_ack)
# ----------- TCP Keep-Alive -----------


time.sleep(30)
print("---------- TCP Fin ----------")

# ----------- TCP FIN -----------
tcp_fin = TCP(sport=SRC_PORT, dport=DST_PORT, flags='F', seq=client_seq)

response_tcp_fin = sr1(ip/tcp_fin, timeout=5)
print(response_tcp_fin)
client_seq = response_tcp_fin.ack
tcp_ack.seq = client_seq
tcp_ack.ack = response_tcp_fin.seq + 1
send(ip/tcp_ack)
# ----------- TCP FIN -----------

print("---------- TCP Fin - Done ----------")