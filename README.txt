#THIS README EXPLAINS THE STRUCTURE OF THE CapturePacket MODULE

Functions --> verb_name (ex. extract_packet())
Classes --> starts with _, First letter of every word is Uppercase, words separated by _ (ex. _EthernetHeader)
Class variables -->First letter of every word is Uppercase, words not separated (ex. EthernetHeader)
Class Instances --> first 3 or 4 lettres of classname + Class (ex. EthClass)
normal variables --> always lowercase, words separated by _ (ex. ethernet_header)

HOW TO USE THIS MODULE
#IMPORT the module
from Capture-Packet import *

#Create a socket --> returns socket
sock = create_socket()

#Second, extract a packet from the socket --> returns Packet instance
while True:
	pack = extract_packet(sock)

#Use instance.Attribute to access data, examples below
pack.Length 							#returns packet length in bytes
pack.DataLinkHeader 					#returns Ethernet_Header instance from Packet object pack
pack.DataLinkHeader.SourceMAC 			#returns Source MAC address from Ethernet_Header instance from Packet object pack
pack.DataLinkHeader.VLAN[0].TPID 		#returns TPID from the first VLAN of the ethernet header from Packet object pack


CLASSES
_Packet:
	Length #number of bytes in this packet
	Content #string of bytes, representing the packet
	DataLinkHeader #Ethernet_Header object [source_MAC, destination_MAC, protocol, VLAN_count, VLAN[]]
	NetworkProtocol #used network layer protocol in string (IPv4/6...)
	NetworkHeader #Network layer header
	TransportProtocol #used transport layer protocol in string (UDP/TCP...)
	TransportHeader #Transport layer header
	
_EthernetHeader:
	Length #Ethernet header length, default 14
	SourceMAC #the source MAC address
	DestinationMAC #the destination MAC address
	Protocol #Network layer protocol in hex
	Payload #Packet size if no EtherType present
	VLANCount #number of VLANs in this packet, default 0
	VLAN #array of VLAN objects

_VLANTag:
	TPID #VLAN TPID
	PCP	#VLAN PCP
	DEI #VLAN DEI
	
_IPv4Header:
	Length #default 20
	Protocol #Transport layer protocol in hex
	Version
	IHL
	TTL
	SourceAddress #Source IPv4 in 0.0.0.0 notation
	DestinationAddress #Destination IPv4 in 0.0.0.0 notation
	
_ARPHeader:
	Length #default 8
	Protocol
	DataLinkProtocol #Used layer 2 protocol (usually Ethernet)
	NetworkProtocol #Used layer 3 protocol (usually IPv4)
	HardwareAddressLength #length of layer 2 address (usually MAC)
	ProtocolAddressLength #length of layer 3 address (usually IPv4)
	Operation #indicates send/receive/other messages
	HardwareAddressSender #usually MAC address in 0:0:0:0:0:0 notation
	HardwareAddressTarget #usually MAC address in 0:0:0:0:0:0 notation
	ProtocolAddressSender #usually IPv4 address in 0.0.0.0 notation
	ProtocolAddressTarget #usually IPv4 address in 0.0.0.0 notation
	
_IPv6Header:
	Length #default 40
	Protocol
	Version
	TrafficClass
	FlowLabel
	PayloadLength
	NextHeader
	HopLimit
	SourceAddress #source IPv6 address, type IPv6Address
	DestinationAddress #destination IPv6 address, type IPv6Address

_IPv6Address:
	Address #actual address
	Type #link-local/global unicast etc.
	TypeNumber
	GlobalRoutingPrefix
	SubnetID
	InterfaceID
	LocalBit
	GlobalID
	Flags
	Scope
	GroupID

_TCPHeader:
	Length
	SourcePort
	DestinationPort
	Sequence
	Acknowledgement
	DataOffsetReserved
	Data

_UDPHeader:
	Length
	SourcePort
	DestinationPort
	Checksum
	Data

_ICMPHeader:
	Length
	Type
	Code
	Checksum
	Data

TREE STRUCTURE (for easy calling)
Packet:
	Length
	Content
	DataLinkHeader
		Length
		SourceMAC
		DestinationMAC
		Protocol
		Payload
		VLANCount
		VLAN[]
			TPID
			PCP
			DEI
	HexNetworkProtocol
	NetworkProtocol
	NetworkHeader
		Length
		Protocol
		
		#if PROTOCOL IPv4
		Version
		IHL
		TTL
		SourceAddress
		DestinationAddress
		
		#if PROTOCOL ARP
		DataLinkProtocol
		NetworkProtocol
		HardwareAddressLength
		ProtocolAddressLength
		Operation
		HardwareAddressSender
		ProtocolAddressSender
		HardwareAddressTarget
		ProtocolAddressTarget
		
		#if PROTOCOL IPv6
		Length
		Protocol
		Version
		TrafficClass
		FlowLabel
		PayloadLength
		NextHeader
		HopLimit
		SourceAddress
			Address
			Type
			TypeNumber
			GlobalRoutingPrefix
			SubnetID
			InterfaceID
			LocalBit
			GlobalID
			Flags
			Scope
			GroupID
		DestinationAddress
			Address
			Type
			TypeNumber
			GlobalRoutingPrefix
			SubnetID
			InterfaceID
			LocalBit
			GlobalID
			Flags
			Scope
			GroupID
	HexTransportProtocol
	TransportProtocol
	TransportHeader
		#if PROTOCOL TCP
		Length
		SourcePort
		DestinationPort
		Sequence
		Acknowledgement
		DataOffsetReserved
		Data
		
		#if PROTOCOL UDP
		Length
		SourcePort
		DestinationPort
		Checksum
		Data
		
		#if PROTOCOL ICMP
		Length
		Type
		Code
		Checksum
		Data


#How the GUI works
The _MasterThread class creates:
	Start Button
	Pause Button
	Stop Button
	Text Frame (including scrollbar)
	Packet sniffer thread #adds packets to the queue
	Main loop #processes the packets from the queue and prints them in the Text Frame

You are free to add your own functionality. It's as simple as creating a new thread and starting it in the _MasterThread.
Define a function and communicate through a new queue. Dont forget to shut down your subprocesses before shutting down the main loop!