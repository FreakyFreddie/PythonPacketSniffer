#THIS CODE CAPTURES NETWORK PACKETS
#Only works for LINUX systems

#Socket library - neccessary to set up and extract data from sockets
import socket

#Struct library - neccessary to unpack hex structs
import struct

#Sys library - neccessary for exit() and other sys functions
import sys

#Date library - needed for the errorlog
from datetime import datetime

#Creating a socket to capture all packets
def create_socket():
	#errorhandling
	try:
		#AF_PACKET 
		#SOCK_RAW receives both UDP AND TCP traffic
		#ntohs(0x0003) = ETH_P_ALL
		#network byte order to host byte order
		sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
		return sock

	except socket.error, errormsg:
		#writing error message to log file
		errorlog = open('errorlog.txt', 'a')
		errorlog.write(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + ' Socket creation failed. Code: ' + str(msg[0]) + 'Message ' + msg[1] + '\n')
		errorlog.close
		sys.exit()

#MAC address structure
#% indicates we want to format everything between parentheses
#.2 indicates that we always want a minimum of 2 hex numbers before each colon
#x indicates the Signed hexadecimal (lowercase) format
#ord() returns an integer representing the unicode point of the string character
def MAC_address(packet):
	MAC = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(packet[0]), ord(packet[1]), ord(packet[2]), ord(packet[3]), ord(packet[4]), ord(packet[5]))
	return MAC

#Datalink Layer Protocol [only ETHERNET supported]
#Extracting packets from socket
def extract_packet(sock):
	#packetlog = open('packetlog.txt', 'a')

	#returns packet in hex from socket with bufsize 65565
	#returns packet as string
	packet = sock.recvfrom(65565)

	#debug
	print packet
	
	#The length of the ethernet header is 14 bytes (layer 2 ethernet frame)
	eth_length = 14
	
	#we only need the unfiltered binary data
	packet = packet[0]
	
	#First 14 bytes are ethernet header	
	eth_header = packet[0:eth_length]

	#							ETHERNET HEADER
	#0                   1                   2                   3
	#0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	#|				 Ethernet dest (last 32 bits)			     |
	#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	#| Ethernet dest (last 16 bits)  |Ethernet source (first 16 bits)|
	#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	#|				 Ethernet source (last 32 bits)				     |
	#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	#|       VLAN (optional-32bits)		 |      	 EtherType		 |
	#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		
	#Unpack eth_header string according to the given format !6s6sH
	#!indicates we don't know if the data is big or little endian
	#s indicates a string of characters (6xchar 6xchar)
	#H indicates an unsigned short int (1xunsigned short int)
	#Char is 1 byte, short int is 2 bytes
	#MAC address format is 6 groups of 2 hexadecimal digits
	eth = struct.unpack('!6s6sH', eth_header)

	#protocol used is short int from eth_header
	#NOTE: Some systems use little endian order (like intel)
	#we need to swap the bytes on those systems to get a uniform result
	#ntohs switches network byte order to host byte order
	#should any byte order problems occur, try implementing the ntohs function
	eth_protocol = eth[2]
	
	#VLAN counter
	VLAN_number = 0
	
	#check if VLAN tag is present
	while eth_protocol == 33024:
		#VLAN tag structure:
		#16 bits Tag Protocol Identifier (TPID) = 0x8100 or 33024
		#3 bits Priority Code Point (PCP)
		#1 bit Drop Eligible Indicator (DEI)
		#12 bit VLAN Identifier (VID)
		#Ethernet header grows bigger by 32 bits
		#parse VLAN tag (4bytes, eth_protocol included in the last 2 bytes)
		VLAN_tag_data = packet[eth_length:eth_length+4]
		
		#unpack VLAN tag
		VLANt = struct.unpack('!HH', VLAN_tag_data)
		
		VLANt_PCP = VLANt[0] >> 13 #nog bitmasken
		VLANt_DEI = VLANt[0] >> 12 #nog bitmasken
		VLANt_VID = VLANt[0] & #nog bitmasken
		
		eth_length += 4
		eth_protocol = VLANt[1]
		
		#number of VLAN tags depends on the number of VLAN frames
		VLAN_number += 1
		

	#write MAC addresses to file
	print 'Destination MAC : ' + MAC_address(packet[0:6]) + ' Source MAC : ' + MAC_address(packet[6:12]) + ' Protocol : ' + str(eth_protocol)

	#remove ethernet header from packet
	packet = packet[eth_length:]
	
	#eth_protocol 1500 or less? The number is the size of ethernet frame payload
	#above 1500 indicates ethernet II frame
	if eth_protocol <= 1500:
		print ' payload = ' + str(eth_protocol)
		print ' Protocols not supported '

	#ethertypes:
	#hex            name            decimal
	#0800           IPv4            2048
	#0806           ARP             2054
	#86DD           IPv6            34525
	#append list to listen in on other protocols
	elif eth_protocol == 2048:
			IPv4(packet)
	elif eth_protocol == 2054:
			ARP(packet)
	elif eth_protocol == 34525:
			IPv6(packet)
	else:
		print 'Protocol not supported.'

#Network Layer Protocols
def IPv4(packet):
	#The length of the IPv4 header is 20 bytes
	IPv4_length = 20

	#parse the IPv4 header (first 20 characters after ethernet header)
	IPv4_header = packet[0:IPv4_length]

	#							IPv4 HEADER
	#0                   1                   2                   3
	#0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	#|Version|  IHL  |Type of Service|          Total Length         |
	#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	#|         Identification        |Flags|      Fragment Offset    |
	#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	#|  Time to Live |    Protocol   |         Header Checksum       |
	#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	#|                       Source Address                          |
	#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	#|                    Destination Address                        |
	#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+      

	#unpacking the IPv4 header
	#B unpacking to unsigned char
	#H unpacking to unsigned short int
	#s unpacking to string of 4 chars
	IPv4h = struct.unpack('!BBHHHBBH4s4s', IPv4_header)


	#version and internet header length (ihl) are in the first unsigned char
	IPv4h_version_ihl = IPv4h[0]

	#to get IPv4 version, shift 4 MSB 4 positions right
	IPv4h_version = (IPv4h_version_ihl >> 4) & 0xF

	#to get IPv4 internet header length, we need the 4 LSB
	#ihl & 00001111
	IPv4h_ihl = IPv4h_version_ihl & 0xF

	#ihl is the number if 32bit words in the header
	#IPv4h_length is in bytes (*4)
	IPv4h_length = IPv4h_ihl * 4

	#IPv4_ttl is unpacked on 6th position
	#B(1byte) B(1byte) H(2bytes) H(2bytes) H(2bytes) B(1byte)
	#TTL = last B
	IPv4h_ttl = IPv4h[5]

	#IPv4 protocols:
	#hex            name            decimal
	#0006           TCP             6
	#0011           UDP             17
	#0001           ICMP            1
	#append list to listen in on other protocols
	#IPv4 protocol number is an unsigned char
	IPv4h_protocol = IPv4h[6]

	#convert packed source and destination IPv4 address to correct format
	#4s 4s was used to unpack
	IPv4h_source_address = socket.inet_ntoa(IPv4h[8])
	IPv4h_destination_address = socket.inet_ntoa(IPv4h[9])

	print 'Version : ' + str(IPv4h_version) + ' IP Header Length : ' + str(IPv4h_ihl) + ' TTL : ' + str(IPv4h_ttl) + ' Protocol: ' + str(IPv4h_protocol) + ' Source IP: ' + str(IPv4h_source_address) + ' Destination IP: ' + str(IPv4h_destination_address)

	#remove IPv4 header from packet
	packet = packet[IPv4_length:]
	
	#IPv4 protocols:
	#hex		name		decimal
	#0006		TCP			6
	#0011		UDP			17
	#0001		ICMP		1
	#append list to listen in on other protocols
	if IPv4h_protocol == 6:
		TCP(packet)
	elif IPv4h_protocol == 17:
		UDP(packet)
	elif IPv4h_protocol == 1:
		ICMP(packet)
	else:
		print 'Protocol not supported.'
	
def ARP(packet):
	#ARP header length is 8 bytes
	ARP_length = 8
	
	#parse the ARP header 
	ARP_header = packet[0:ARP_length]
	
	#							ARP HEADER
	#0                   1                   2                   3
	#0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	# 			Hardware type		 | 	  	  Protocol type 		 |
	#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	#|MAC address len|Proto address l|            Operation          |
	#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	#|  				  Sender hardware address    				 |
	#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	#|            ...                |   Sender protocol address     |
	#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	#|            ...                |   Target hardware address     |
	#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
	#|                              ...                              |
	#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
	#|   				   Target protocol address                   |
	#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 

	#unpack ARP header
	#H for hardware type (2bytes)
	#H for protocol type (2bytes)
	#H for Mac address length and protocol address length (2bytes)
	#2s for operation (2bytes)

	ARPh = struct.unpack('!HHHH', ARP_header)
	
	#extract info
	#network protocol/hardware type (ex. ethernet = 1)
	ARPh_network_protocol = ARPh[0]
	ARPh_protocol_type = ARPh[1]
	ARPh_hardware_address_length = (ARPh[2] >> 8) & 0xF
	ARPh_protocol_address_length = ARPh[2] & 0xF
	ARPh_operation = ARPh[3]

	#remove first 8 bytes from packet since we already unpacked them
	packet = packet[ARP_length:]
	
	#unpack hardware address sender
	#we need the length to unpack (ex MAC address is 6s)
	ARP_hardware_address_sender = packet[0:ARPh_hardware_address_length]
	unpack_format_hardware = '!' + str(ARPh_hardware_address_length) + 's'
	ARPh_hardware_address_sender = struct.unpack(unpack_format_hardware, ARP_hardware_address_sender)
	
	#remove ARPh_hardware_address_length from packet since we already unpacked it
	packet = packet[ARPh_hardware_address_length:]
	
	#unpack protocol address sender
	ARP_protocol_address_sender = packet[0:ARPh_protocol_address_length]
	unpack_format_protocol = '!' + str(ARPh_protocol_address_length) + 's'
	ARPh_protocol_address_sender = struct.unpack(unpack_format_protocol, ARP_protocol_address_sender)
	
	#remove ARPh_protocol_address_length from packet since we already unpacked it
	packet = packet[ARPh_protocol_address_length:]
	
	#unpack hardware address target
	ARP_hardware_address_target = packet[0:ARPh_hardware_address_length]
	ARPh_hardware_address_target = struct.unpack(unpack_format_hardware, ARP_hardware_address_target)
	
	#remove ARPh_hardware_address_length from packet since we already unpacked it
	packet = packet[ARPh_hardware_address_length:]
	
	#unpack protocol address target
	ARP_protocol_address_target = packet[0:ARPh_protocol_address_length]
	ARPh_protocol_address_target = struct.unpack(unpack_format_protocol, ARP_protocol_address_target)
	
	#remove ARPh_protocol_address_length from packet since we already unpacked it
	packet = packet[ARPh_protocol_address_length:]
	
	#Hardware address to correct format
	#if we use ethernet address (MAC), we don't need the unpacked address
	#MAC_address() function will do the conversion for us
	if ARPh_network_protocol == 1:
		ARPh_hardware_address_sender = MAC_address(ARP_hardware_address_sender)
		ARPh_hardware_address_target = MAC_address(ARP_hardware_address_target)
	else:
		print 'Protocol type not supported'
	
	#Protocol address to correct format
	#if we use IP address (IPv4), we don't need the unpacked address
	#socket.inet_ntoa() function will do the conversion for us
	if ARPh_protocol_type == 2048:
		ARPh_protocol_address_sender = socket.inet_ntoa(ARP_protocol_address_sender)
		ARPh_protocol_address_target = socket.inet_ntoa(ARP_protocol_address_target)
	else:
		print 'Protocol type not supported'
	
	print 'ARP PACKET: '+ str(ARPh_network_protocol) + '  ' + str(ARPh_protocol_type) + '  ' + str(ARPh_hardware_address_length) + '  ' + str(ARPh_protocol_address_length)
	print str(ARPh_operation) + '  ' + str(ARPh_protocol_address_sender) + '  ' + str(ARPh_protocol_address_target)
	print str(ARPh_hardware_address_sender) + '  ' + str(ARPh_hardware_address_target)
	
#Transport Layer Protocols
def TCP(packet):
	#The length of the TCP header is 20 bytes
	TCP_length = 20
	
	#parse the TCP header
	TCP_header = packet[0:TCP_length]
	
	#							TCP HEADER
	#0                   1                   2                   3
	#0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	#|          Source Port          |       Destination Port        |
	#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	#|                        Sequence Number                        |
	#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	#|                    Acknowledgment Number                      |
	#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	#|  Data |           |U|A|P|R|S|F|                               |
	#| Offset| Reserved  |R|C|S|S|Y|I|            Window             |
	#|       |           |G|K|H|T|N|N|                               |
	#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	#|           Checksum            |         Urgent Pointer        |
	#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	#|                    Options                    |    Padding    |
	#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	#|                             data                              |
	#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

	#unpacking the TCP header
	#H unpacking to unsigned short int
	#L unpacking to unsigned long int (32bit)
	#B unpacking to unsigned char
	TCPh = struct.unpack('!HHLLBBHHH', TCP_header)
	
	#extract info
	TCP_source_port = TCPh[0]
	TCP_destination_port = TCPh[1]
	TCP_sequence = TCPh[2]
	TCP_acknowledgement = TCPh[3]
	TCP_Data_Offset_reserved = TCPh[4]
	
	#extract TCP length in bytes
	#options & padding may vary
	TCPh_length = TCP_Data_Offset_reserved >> 4
	TCPh_length = TCPh_length * 4

	print 'Source Port : ' + str(TCP_source_port) + ' Dest Port : ' + str(TCP_destination_port) + ' Sequence Number : ' + str(TCP_sequence) + ' Acknowledgement : ' + str(TCP_acknowledgement) + ' TCP header length : ' + str(TCPh_length)

	#extract data
	TCP_data = packet[TCPh_length:]
	
	#print data for now
	print 'Data : ' + TCP_data	

def UDP(packet):
	#UDP header length is 8 bytes
	UDP_length = 8
	
	#parse the UDP header
	UDP_header = packet[0:UDP_length]
	
	#							UDP HEADER
	#0                   1                   2                   3
	#0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	#|          Source Port          |       Destination Port        |
	#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	#|          Length               |       Checksum                |
	#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+	
	#..............................DATA...............................
	
	#unpacking the UDP header
	UDPh = struct.unpack('!HHHH', UDP_header)
	
	#Extract info
	UDPh_source_port = UDPh[0]
	UDPh_destination_port = UDPh[1]
	UDPh_length = UDPh[2]
	UDPh_checksum = UDPh[3]
	
	print 'Source Port : ' + str(UDPh_source_port) + ' Dest Port : ' + str(UDPh_destination_port) + ' Length : ' + str(UDP_length) + ' Checksum : ' + str(UDPh_checksum)
	
	#extract data
	UDP_data = packet[UDP_length:]
	
	#print data for now
	print 'Data : ' + UDP_data
	
def ICMP(packet):
	#ICMP header length is 4 bytes
	ICMP_length = 4
	
	#parse ICMP header
	ICMP_header = packet[0:ICMP_length]

	#unpack ICMP header
	ICMPh = struct.unpack('!BBH' , ICMP_header)
	
	#							ICMP HEADER
	#0                   1                   2                   3
	#0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	#|		Type	 | 		Code     |           Checksum            |
	#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	#|                        Rest of header	                     |
	#+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	
	#extract info
	ICMPh_type = ICMPh[0]
	ICMPh_code = ICMPh[1]
	ICMPh_checksum = ICMPh[2]
	
	print 'Type : ' + str(ICMPh_type) + ' Code : ' + str(ICMPh_code) + ' Checksum : ' + str(ICMPh_checksum)
	
	#extract data
	ICMP_data = packet[ICMP_length:]
	
	#print data for now
	print 'Data : ' + ICMP_data
	
sock=create_socket()
while True:
        extract_packet(sock)