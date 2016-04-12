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