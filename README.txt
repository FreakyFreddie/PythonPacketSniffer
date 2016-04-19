README

Functions --> verb_name (ex. extract_packet())
Classes --> starts with _, First letter of every word is Uppercase, words separated by _ (ex. _EthernetHeader)
Class variables -->First letter of every word is Uppercase, words not separated (ex. EthernetHeader)
Class Instances --> first 3 or 4 lettres of classname + Class (ex. EthClass)
normal variables --> always lowercase, words separated by _ (ex. ethernet_header)

HOW TO USE THIS MODULE
#First, create a socket --> returns socket
sock = create_socket()

#Second, extract a packet from the socket --> returns Packet instance
pack = extract_packet(sock)

#Use instance.Attribute to access data, examples below
pack.Length 							#returns packet length in bytes
pack.DataLinkHeader 					#returns Ethernet_Header instance from Packet object pack
pack.DataLinkHeader.SourceMAC 			#returns Source MAC address from Ethernet_Header instance from Packet object pack
pack.DataLinkHeader.VLAN[0].TPID 		#returns TPID from the first VLAN of the ethernet header from Packet object pack

#IPv4 options nog toevoegen

CLASSES
Packet:
	Length #number of bytes in this packet
	Content #string of bytes, representing the packet
	DataLinkHeader #Ethernet_Header object [source_MAC, destination_MAC, protocol, VLAN_count, VLAN[]]
	NetworkHeader #
	TransportHeader #
	
Ethernet_Header:
	SourceMAC #the source MAC address
	DestinationMAC #the destination MAC address
	Protocol #Protocol number (ex. 2048 = IPv4)
	VLANCount #number of VLANs in this packet
	VLAN #array of VLAN objects
	
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
		#PROTOCOL IPv4
		Version
		IHL
		TTL
		SourceAddress
		DestinationAddress
		#PROTOCOL ARP
		DataLinkProtocol
		NetworkProtocol
		HardwareAddressLength
		ProtocolAddressLength
		Operation
		HardwareAddressSender
		ProtocolAddressSender
		HardwareAddressTarget
		ProtocolAddressTarget
		
	TransportHeader

Functions