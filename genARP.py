from scapy.all import *
COUNT = 1000

#pkt = Ether(src="22:fb:7c:f2:71:d0", dst="ff:ff:ff:ff:ff:ff")/ARP(op=ARP.who_has, hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.1.2", hwsrc="22:fb:7c:f2:71:d0", psrc="192.168.1.99" )

pkt = Ether(src="00:00:00:00:0a:0a", dst="ff:ff:ff:ff:ff:ff")/ARP(op=ARP.who_has, hwdst="ff:ff:ff:ff:ff:ff", pdst="192.168.1.97", hwsrc="00:00:00:00:0a:0a", psrc="192.168.1.95" )
for _ in range(COUNT):
    sendp(pkt)
