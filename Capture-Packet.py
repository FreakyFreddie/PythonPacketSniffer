#THIS CODE CAPTURES NETWORK PACKETS

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
			errorlog.write(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') + ' Socket creation failed. Code: ' + str(msg[0]) + 'Message ' + msg[1] + '\n')
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

#Extracting packets from socket
def extract_packet(sock):
	packetlog = open('packetlog.txt', 'a')

	#returns packet in hex from socket with bufsize 65565
	#returns packet as string
	packet = sock.recv(65565)

	#The length of the ethernet header is 14 bytes (layer 2 ethernet frame)
	eth_length = 14

	#First 14 bytes are ethernet header
	eth_header = packet[0:eth_length]

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

	#write MAC addresses to file
	print 'Destination MAC : ' + MAC_address(packet[0:6]) + ' Source MAC : ' + MAC_address(packet[6:12]) + ' Protocol : ' + str(eth_protocol)

	#remove ethernet header from packet
	packet = packet[eth_length:]
	
	#ethertypes:
	#hex            name            decimal
	#0800           IPv4            2048
	#0806           ARP                     2054
	#86DD           IPv6            34525
	#append list to listen in on other protocols

	if eth_protocol == 2048:
			IPv4(packet)
	elif eth_protocol == 2054:
			ARP(packet)
	elif eth_protocol == 34525:
			IPv6(packet)

def IPv4(packet):
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
	#0006           TCP                     6
	#0011           UDP                     17
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
	
def IPv6(packet):
	
	
def TCP(packet):
	

def UDP(packet):
	

def ICMP(packet):
	
	

	

#while True:
#        sock=create_socket()
#        extract_packet(sock)