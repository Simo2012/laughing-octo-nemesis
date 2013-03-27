import pcapy
import impacket.ImpactDecoder as Decoders
import impacket.ImpactPacket as Packets

try:
 import dpkt
except:
 print "downlods dpkt"
try:
 import glob
except:
 print "downlods glob"
try:
 import pcap
except:
 print "downlods pcap"
try:
 import socket
except:
 print "downlods socket"
try:
 import os
except:
 print "downlods os"
try:
 f = open('capture.cap')
 capture = dpkt.pcap.Reader(f)
except:
 print "impossible open pcap"
chaine=""
chaine2=""

eth_decoder = Decoders.EthDecoder()
ip_decoder = Decoders.IPDecoder()
udp_decoder = Decoders.UDPDecoder()
tcp_decoder = Decoders.TCPDecoder()
data_decoder = Decoders.DataDecoder()

for i,packet in capture:
   
    #E..?.U@.@.EB....>.a.....]....@..P...."..SSH-1.99-OpenSSH_2.9p2
    #SSH filtre port 22 dp et sp ,recuperer la data en binaire et tester SSH-, afficher la version(protoco
  
    
    eth = dpkt.ethernet.Ethernet(packet)
    if type(eth.data) != dpkt.ip.IP:
        continue 
    ip = eth.data
    if type(ip.data) != dpkt.tcp.TCP:
        continue
    tcp = ip.data
    src = socket.inet_ntoa(ip.src)
    dst = socket.inet_ntoa(ip.dst) 
    if tcp.dport == 22 and len(tcp.data) > 0:
         ethernet = eth_decoder.decode(packet)
         if ethernet.get_ether_type() == Packets.IP.ethertype:
            ip = ip_decoder.decode(packet[ethernet.get_header_size():])
            if ip.get_ip_p() == Packets.TCP.protocol: 
             data  = data_decoder.decode(packet)           
             print data
    if tcp.sport == 22 and len(tcp.data) > 0:
         ethernet = eth_decoder.decode(packet)
         if ethernet.get_ether_type() == Packets.IP.ethertype:
            ip = ip_decoder.decode(packet[ethernet.get_header_size():])
            if ip.get_ip_p() == Packets.TCP.protocol: 
             data  = data_decoder.decode(packet)           
             print data
    if tcp.dport == 80 and len(tcp.data) > 0:
               httpReq = dpkt.http.Request(tcp.data)
               try:
	         if len(httpReq.headers['user-agent'])>0 :
                    #print src, " | user-agent: " , httpReq.headers['user-agent'] , " | URI: " , httpReq.uri , " | Type: " , httpReq.method
		    chaine = src + " | user-agent: " , httpReq.headers['user-agent'] , " | URI: " , httpReq.uri , " | Type: " , httpReq.method
		 continue
	       except:
                 pass 
    if tcp.sport == 80 and len(tcp.data) > 0:
               try:
                   httpRes = dpkt.http.Response(tcp.data)
                   if len(httpRes.headers['server'])>0:
                     chaine2  = "| server: " ,httpRes.headers['server'] 
                   continue
           
               except:
                   pass

    if len(chaine) > 0 :
           #chaine3 = chaine + chaine2
           print chaine, chaine2
           chaine = ""
           chaine2 = ""
                

              
               
	       
   



