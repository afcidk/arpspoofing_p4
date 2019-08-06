from scapy.all import *
COUNT = 1000

pkt = Ether(src="00:00:00:00:0a:0a", dst="ff:ff:ff:ff:ff:ff")/ARP(op=ARP.who_has, hwdst="ff:ff:ff:ff:ff:ff", pdst="1.2.3.4", hwsrc="00:00:00:00:0a:0a", psrc="192.168.1.80", )

for _ in range(COUNT):
    sendp(pkt)
