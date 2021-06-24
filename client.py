import socket
from scapy.all import *
import hashlib

#The client will send a syn packet to the server
#after sending the packet he will wait for answer for about 3 seconds
#If the client will not recieve syn-ack packet from the server he will send packet again



kali
#After the client get message that the handshake approved,
#the client will start the socket communication

ip = "192.168.56.101"
syn_packet = IP(dst=ip)/TCP(dport=8000, flags ="S")
synack = sr1(syn_packet)
synack.show()
ack = IP(dst=ip)/TCP(dport=synack["TCP"].sport, flags = "A", ack= synack["TCP"].seq+1)
print(ack.show())
send(ack)
#syn_ack = sr1(syn_packet)
