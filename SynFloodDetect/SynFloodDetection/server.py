import tkinter.ttk
from queue import Queue
from scapy.all import *
from scapy.layers.inet import IP, TCP
import threading
from tkinter import *
from tkinter.ttk import Progressbar

import time
#logging.basicConfig(level=logging.DEBUG,format='(%(threadName)-9s) %(message)s',)

def port_rst_drop():
    """
    Drop kernel auto RST responses to packets that come into a specific port
    :return: None
    """
    os.system("sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport 8000 -j DROP")


class ThreadQueue(object):
    def __init__(self, maxsize=0):
        self.lock = threading.Lock()
        self.queue = Queue(maxsize)

    def length(self):
        logging.debug('Waiting for a lock')
        self.lock.acquire()
        info = self.queue.qsize()
        self.lock.release()
        logging.debug('Released a lock')
        return info

    def put(self, value):
        logging.debug('Waiting for a lock')
        self.lock.acquire()
        self.queue.put(value)
        self.lock.release()
        logging.debug('Released a lock')

    def get(self):
        logging.debug('Waiting for a lock')
        self.lock.acquire()
        value = self.queue.get()
        self.lock.release()
        logging.debug('Released a lock')
        return value

    def empty(self):
        logging.debug('Waiting for a lock')
        self.lock.acquire()
        if self.queue.empty():
            self.lock.release()
            logging.debug('Released a lock')
            return True
        else:
            self.lock.release()
            logging.debug('Released a lock')
            return False

    def list(self):
        logging.debug('Waiting for a lock')
        self.lock.acquire()
        lst = self.queue.queue
        self.lock.release()
        logging.debug('Released a lock')
        return lst

    def clear(self):
        logging.debug('Waiting for a lock')
        self.lock.acquire()
        q = self.queue
        with q.mutex:
            q.queue.clear()
        self.lock.release()
        logging.debug('Released a lock')
        print("Clear syn-ack sends")


class UnderAttack(Thread):
    def __init__(self, file):
        super(UnderAttack, self).__init__()

        self.file = file
        self.flag = False

    def run(self):
        while True:
            if self.flag:
                os.system("mpg123 " + self.file)

                self.flag=False


class ThreadList(object):
    def __init__(self):
        self.lock = threading.Lock()
        self.list = []

    def append(self, value):
        logging.debug('Waiting for a lock')
        self.lock.acquire()
        self.list.append(value)
        self.lock.release()
        logging.debug('Released a lock')

    def remove(self, value):
        logging.debug('Waiting for a lock')
        self.lock.acquire()
        self.list.remove(value)
        self.lock.release()
        logging.debug('Released a lock')

    def length(self):
        logging.debug('Waiting for a lock')
        self.lock.acquire()
        info = len(self.list)
        self.lock.release()
        logging.debug('Released a lock')
        return info

    def clear(self):
        logging.debug('Waiting for a lock')
        self.lock.acquire()
        self.list.clear()
        self.lock.release()
        logging.debug('Released a lock')


PacketFilter = ThreadQueue()
AcceptQueue = ThreadQueue(1000)
SendPackets = ThreadQueue()
OpenConnection = ThreadList()
ApprovedConnection = ThreadQueue()

# Queue for handle all wait for ack
# [{"pkt:packet, time: time.time()},]
SynList = ThreadList()
# Queue for handle all ACK packets
AckQueue = ThreadQueue(1000)
MaxHalfConnections = 1000
PORT = 8000



class SendPacket(Thread):
    def run(self) -> None:
        while True:
            if not SendPackets.empty():
                send(SendPackets.get(), verbose=False)
                time.sleep(0.001)


def packet_transfer(pkt):
    connection = {"IP": pkt["IP"].src, "SPORT": pkt["TCP"].sport}
    # Check if the user already have a connection to the server
    if IP in pkt and connection in AcceptQueue.list():
        # Send packet to start get data
        ApprovedConnection.put(pkt)
    else:
        # Send packet to create 3 way handshake
        PacketFilter.put(pkt)


class PacketsOrganize(Thread):
    """
     Listen to all packets that coming through a specific port.
    """

    def run(self):
        print("Start sniffing")
        # Sniff tcp packets with specific port
        sniff(filter="tcp and dst port " + str(PORT), prn=packet_transfer, store=0)


def syn_ack_create(packet):
    """
    Create an syn-ack packet, add him to queue sender, create listen dictionary
    :param packet: syn scapy packet
    :return: ack packet + time create packet
    """
    daddr = packet["IP"].dst
    saddr = packet["IP"].src
    sport = packet["TCP"].sport
    dport = packet["TCP"].dport
    SeqNr = packet["TCP"].seq
    AckNr = packet["TCP"].seq + 1
    # Create syn-ack packet with scapy
    synack = IP(dst=saddr) / TCP(sport=dport, dport=sport, flags="SA", seq=SeqNr, ack=AckNr)
    # Need ro send synack
    SendPackets.put(synack)
    ACK = IP(dst=daddr, src=saddr) / TCP(sport=sport, dport=dport, flags="A", ack=SeqNr + 1)

    timer = time.time()
    packet = {"pkt": ACK, "time": timer}
    return packet


def time_check(timer):
    """
    Check if the half connection is still relevant.
    If yes return True
    else:
    Return False
    :param timer: The time the packet saved in SynList
    :return: bool
    """
    if time.time() - timer < 20:
        return True
    else:
        return False


class PacketSplitter(Thread):

    def run(self):
        """
        Split between syn packets and ack packets
        :return: None
        """

        while True:
            if not PacketFilter.empty():
                packet = PacketFilter.get()
                Flag = packet['TCP'].flags
                SYN = 0x02
                ACK = 0x10
                # Check if packet flag is SYN and the queue is full
                if Flag & SYN and SynList.length() < MaxHalfConnections:

                    packet = syn_ack_create(packet)
                    # Add packet to SynQueue (need to change description)
                    SynList.append(packet)
                elif Flag & ACK:
                    # Add packet to AckQueue (need to change description)
                    print(packet.show())
                    AckQueue.put(packet)


def add_new_connection(packet):
    saddr = packet["IP"].src
    SPORT = packet["TCP"].sport
    CompleteConnection = {"IP": IP, "SPORT": SPORT}
    # Add packet to Established connections
    AcceptQueue.put(CompleteConnection)

    print("Connection established!! \n ip:", saddr + "\n port:", SPORT)

def verify_user(pkt1, pkt2):
    try:
        print(pkt1["IP"].src , pkt2["IP"].src, pkt1["IP"].dst , pkt2["IP"].dst, pkt1["TCP"].dport , pkt2["TCP"].dport, pkt1["TCP"].sport , pkt2["TCP"].sport, pkt1["TCP"].ack ,pkt2["TCP"].ack)
        if pkt1["IP"].src == pkt2["IP"].src:
            if pkt1["IP"].dst == pkt2["IP"].dst:
                if pkt1["TCP"].dport == pkt2["TCP"].dport:
                    if pkt1["TCP"].sport == pkt2["TCP"].sport:
                        if pkt1["TCP"].ack == pkt2["TCP"].ack:
                            return True
        return False
    except:
        return False

class SynQueue(Thread):

    def run(self):
        while True:
            # Check if AckQueue is empty
            NewAck = False
            counter = 0
            ACK_Packet = None
            for packet in SynList.list:
                if not AckQueue.empty() and NewAck is False:
                    ACK_Packet = AckQueue.get()
                    NewAck = True
                # Check if ACK packet is match one in the SynQueue
                if verify_user(packet["pkt"], ACK_Packet):
                    add_new_connection(packet["pkt"])
                    SynList.remove(packet)
                    counter =0
                    break
                else:
                    if time_check(packet["time"]):
                        counter += 1
                    else:
                        SynList.remove(packet)
            if counter > int(MaxHalfConnections/1.1):
                print("Syn flood attack detect")
                SynList.clear()
                SendPackets.clear()

class TK():
    def __init__(self):
        self.MaxHalfConnections = 1000
        self.SynPackets =0

        self.root = Tk()

        self.style = tkinter.ttk.Style()
        self.style.theme_use("default")
        self.style.configure("black.Horizontal.TProgressbar", background='black', foreground="blue")
        self.bar = Progressbar(self.root, maximum=self.MaxHalfConnections, length=500, style='black.Vertical.TProgressbar', orient="vertical")



    def attack_text(self):
        var = StringVar()
        var.set("Hey!? How are you doing?")
        self.lab = Label(self.root, textvariable=var, relief=RAISED)
        self.lab.pack()
        self.root.bind("<Return>", self.attack_text)
        self.root.update()
    def progbar(self):

        self.SynPackets = SynList.length()
        self.bar['value'] = self.SynPackets
        self.bar.grid(column=0, row=0)


        time.sleep(0.01)
        self.root.bind("<Return>", self.progbar)
        self.root.update()





class Graphics(Thread):
    def run(self) -> None:
        Graphs = TK()
        Graphs.__init__()

        while True:
            Graphs.progbar()
            Graphs.attack_text()

def main():
    port_rst_drop()
    lst = []

    try:
        lst.append(PacketsOrganize(name="Organize"))
        lst.append(SendPacket(name="Sender"))
        lst.append(PacketSplitter(name="Splitter"))
        lst.append(SynQueue(name="SynQueue"))
        lst.append(Graphics(name="Graphics"))
        for i in lst:
            print(i)
            i.start()

    except ValueError as c:
        print(c)


main()
