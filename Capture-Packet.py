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
def create_socket()
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
def MAC_address(packet):
	MAC = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (hexcode(packet[0], packet[1], packet[2], packet[3], packet[4],  packet[5])
	return MAC
	
#Extracting packets from socket
def extract_packet(sock)
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
	#s indicates a character (6xchar 6xchar)
	#H indicates an unsigned short int (1xunsigned short int)
	#Char is 1 byte, short int is 2 bytes
	#MAC address format is 6 groups of 2 hexadecimal digits
	eth = struct.unpack(!6s6sH, eth_header)
	
	#protocol used is short int from eth_header
		#NOTE: Some systems use little endian order (like intel)
		#we need to swap the bytes on those systems to get a uniform result
		#ntohs switches network byte order to host byte order
		#should any byte order problems occur, try implementing the ntohs function
	eth_protocol = eth[2]
	
	#write MAC addresses to file
	print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)

	#ethertypes:
	#numbers	name		decimal
	#0800		IPv4		2048
	#0806		ARP			2054
	#86DD		IPv6		34525
	#append list to listen in on other protocols
	if eth_protocol == 2048:
		IPv4(packet, eth_length)
	elif eth_protocol == 2054:
		ARP(packet)
	elif eth_protocol == 34525:
		IPv6(packet)