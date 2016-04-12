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
	IPv4h_version = IPv4h_version_ihl >> 4

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
	

def IPv6(packet):
	
def TCP(packet):
	

def UDP(packet):


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
	

#while True:
#        sock=create_socket()
#        extract_packet(sock)