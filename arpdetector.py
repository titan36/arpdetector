#!/usr/bin/python2
import scapy.all as scapy

def get_mac(ip):
    arpObj = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arpObj
   #ans_list, unans_list = scapy.srp(arp_request_broadcast, timeout=1) this is use to see both answeredlsit and unasweredslsit
    clients_list = []
    ans_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return ans_list[0][1].hwsrc
#end of mac finder
def sniff(interface):
	scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
	if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
		try:
			real_mac = get_mac(packet[scapy.ARP].psrc) #this is the real mac of me
			response_mac = packet[scapy.ARP].hwsrc #this is the mack of
			
			if real_mac != response_mac:
				print("[+] you are under atttac")
		except:
			pass	
	
sniff("wlan0")
