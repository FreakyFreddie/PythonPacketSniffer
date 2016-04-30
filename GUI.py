#!/usr/bin/python
#GUI for Python Packet Sniffer

#TKinter tutorial: http://www.tutorialspoint.com/python/python_gui_programming.htm

#Sys library for exit()
import sys

#import Tkinter GUI library
from Tkinter import *
from ttk import *

#import function to close the socket
import socket

#Import threading module since we need to run our packet sniffer in a different thread
#threading module is more powerfull than thread module
import threading

#import Queue for Capture-Packet module thread
import Queue

#import sleep function from time module
from time import sleep

#import the module to capture network packets
from CapturePacket import *

#create GUI class
class _InterfaceGUI:
	def __init__(self, root, queue, startCommand, pauseCommand, endCommand):
		#Set up the queue
		self.queue = queue

		#GUI Frames
		#ButtonFrame for Start, Pause and Stop
		self.ButtonFrame = Frame(root, borderwidth=1, relief=RAISED)

		#ButtonFrame can expand horizontally (X)
		self.ButtonFrame.pack(fill=X)

		#ButtonFrame is the master widget
		#create label for frame
		self.LabelFrame = Frame(self.ButtonFrame)
		self.LabelFrame.pack(fill=X, expand=1)

		self.FrameLabel = Label(self.LabelFrame, text="Control Panel")
		self.FrameLabel.pack(side=LEFT, expand=1, padx=3)

		#create buttons
		self.StartButtonClass = Button(self.ButtonFrame, text="Start", command=startCommand)
		self.PauseButtonClass = Button(self.ButtonFrame, text="Pause", command=pauseCommand)
		self.StopButtonClass = Button(self.ButtonFrame, text="Stop", command=endCommand)

		self.StartButtonClass.pack(side=LEFT, expand=1, padx=3)
		self.PauseButtonClass.pack(side=LEFT, expand=1, padx=3)
		self.StopButtonClass.pack(side=LEFT, expand=1, padx=3)

		#TextFrame for Text widget
		self.TextFrame = Frame(root)

		#TextFrame can expand horizontally (X)
		self.TextFrame.pack(fill=BOTH, expand=1)

		#add scroll bar
		self.TextScroller = Scrollbar(self.TextFrame)
		self.TextScroller.pack(side=RIGHT, fill=Y)
		
		#create actual text frame & bind scrollbar to it
		self.FrameText = Text(self.TextFrame, yscrollcommand=self.TextScroller.set)
		self.FrameText.pack(fill=BOTH, expand=1)
		
		#configure the scrollbar
		self.TextScroller.config(command=self.FrameText.yview)
		
		#start PacketCounter on 0
		self.PacketCounter = 0
		
	#process the current queues
	def process_queue(self, pausecheck):
		while self.queue.qsize() > 0:
			#debug
			print "[Main]\t\tProcessing " + str(self.queue.qsize()) + " packets from queueu"

			#extract a packet from the queue
			pack = self.queue.get(0)
			self.PacketCounter += 1

			#format the packet for printing, each part is one line
			formatted_packet1 = "Packet: " + str(self.PacketCounter) + "\t\tPacket length: " + str(pack.Length) + " \n"
			formatted_packet2 = "\tData Link Protocol: ETHERNET" + "\t\tSource MAC: " + str(pack.DataLinkHeader.SourceMAC) + "\t\tDestination MAC: " + str(pack.DataLinkHeader.DestinationMAC) + " \n"
			
			#check the network protocol
			if pack.DataLinkHeader.Protocol != None:
				if pack.HexNetworkProtocol == 2048:
					formatted_packet3 = "\tNetwork Protocol: " + str(pack.NetworkProtocol) + "\t\tSource IP: " + str(pack.NetworkHeader.SourceAddress) + "\t\tDestination IP: " + str(pack.NetworkHeader.DestinationAddress) + " \n"
				elif pack.HexNetworkProtocol == 2054:
					formatted_packet3 = "\tNetwork Protocol: " + str(pack.NetworkProtocol) + "\t\tSource IP: " + str(pack.NetworkHeader.ProtocolAddressSender) + "\t\tDestination IP: " + str(pack.NetworkHeader.ProtocolAddressTarget) + " \n"
				elif pack.HexNetworkProtocol == 34525:
					formatted_packet3 = "\tNetwork Protocol: " + str(pack.NetworkProtocol) + "\t\tSource IP: " + str(pack.NetworkHeader.SourceAddress.Address) + "\t\tDestination IP: " + str(pack.NetworkHeader.DestinationAddress.Address) + " \n"
				else:
					formatted_packet3 = "\tNetwork protocol not supported. \n"
				
			#check the transport protocol
			if pack.NetworkHeader.Protocol != None:
				if pack.HexTransportProtocol == 1:
					formatted_packet4 = "\tTransport Protocol: " + str(pack.TransportProtocol) + " \n"
				elif pack.HexTransportProtocol == 6:
					formatted_packet4 = "\tTransport Protocol: " + str(pack.TransportProtocol) + "\t\tSource Port: " + str(pack.TransportHeader.SourcePort) + "\t\tDestination Port: " + str(pack.TransportHeader.DestinationPort) + " \n"
				elif pack.HexTransportProtocol == 17:
					formatted_packet4 = "\tTransport Protocol: " + str(pack.TransportProtocol) + "\t\tSource Port: " + str(pack.TransportHeader.SourcePort) + "\t\tDestination Port: " + str(pack.TransportHeader.DestinationPort) + " \n"
				else:
					formatted_packet4 = "\tTransport protocol not supported. \n"
			
			#if pause has been clicked, don't print anything
			#else update the TextFrame's FrameText with the packet info
			if pausecheck != 2:
				self.FrameText.insert(END, formatted_packet1)
				self.FrameText.insert(END, formatted_packet2)
				if pack.DataLinkHeader.Protocol != None:
					self.FrameText.insert(END, formatted_packet3)
				if pack.NetworkHeader.Protocol != None:
					self.FrameText.insert(END, formatted_packet4)
				self.FrameText.insert(END, "\n\n")

class _MasterThread:
	#we launch the sub process and the main thread
	def __init__(self, root):
		#start value
		self.running = 3
		
		#debug
		print "[Main]\tStarting program"
		
		#use the root window we created
		self.root = root

		#debug
		print "[Main]\t\tRoot window created."
		
		#Create the queue (FIFO, NOT LIFO)
		#Queue size defaults to 0 --> Queue can grow infinitly
		self.queue = Queue.Queue()
		
		#debug
		print "[Main]\t\tQueue created."

		#Set up the GUI
		#we pass the queue to the GUI to update the text
		self.gui = _InterfaceGUI(root, self.queue, self.start_packetsniffer, self.pause_packetsniffer, self.end_packetsniffer)
		
		#debug
		print "[Main]\t\tWidgets created."
		
		#create a socket with create_socket() from Capture-Packet
		self.sock = create_socket()
		
		#debug
		print "[Main]\t\tSocket created: " + str(self.sock)
		
		#declare the packet
		self.pack = None
		
		#create the actual thread
		self.PacketSnifferThread = threading.Thread(target=self.packet_sniffer_thread)

		#launch the thread
		self.PacketSnifferThread.start()

		#check if thread is running
		if self.PacketSnifferThread.isAlive() == True:
			#debug
			print "[Main]\t\tPacket sniffer thread running."
			
		#start the programloop
		self.call_programloop()

	def call_programloop(self):	
		#process queue, include pausechecker
		#this function empties the queue
		self.gui.process_queue(self.running)

		#check exit condition
		if self.running == 0:
			#create socket to end the recvfrom() function in extract packet() and connect --> "one last packet"
			temposock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

			#debug
			print "[Main]\tBreaking the packet sniffer loop..."
			
			#dont stop the program on a "connection refused" error, since we only need to send 1 packet
			#random port 1111 chosen
			try:
				temposock.connect((socket.gethostname(), 1111))
			except socket.error:
				pass
			
			#debug
			print "[Main]\tClosing the sockets..."
			
			#close the temporary socket
			temposock.close()
			
			#debug
			print "[Main]\t\tTemporary socket closed."
			
			#close the temporary socket
			self.sock.close()
			
			#debug
			print "[Main]\t\tMain socket closed."
			
			#close the main socket
			self.sock.close()
			
			#when the thread stops, we can exit
			while self.PacketSnifferThread.isAlive() == True:
				#debug
				print "[Main]\tWaiting for packet sniffer thread to die..."
				
				#wait 1 second
				sleep(1)
			
			#debug
			print "[Main]\t\tThread stopped."
			
			#debug
			print "[Main]\tExiting program..."

			#exit the program
			sys.exit()
		
		#test the queue for contents every 1000 milliseconds
		#checks stop button after the queue
		self.root.after(1000, self.call_programloop)

	def packet_sniffer_thread(self):
		#debug
		print "[PSnif]\t\tPacket sniffer thread created."
		
		while True:			
			#run the program until stop/pause
			while self.running == 1:
				#extract a packet from the socket
				#program waits for the socket to return a packet
				#if no packet is received while shutting down, the program cannot fully exit
				self.pack = extract_packet(self.sock)
				#add the packet object to the queue
				self.queue.put(self.pack)

				#debug
				print "[PSnif]\t\tPacket added to queue."

			#exit the wile loop when stopping the program & close thread
			if self.running == 0:
				#debug
				print "[PSnif]\t\tLoop interrupted."
				
				#debug
				print "[PSnif]\tExiting..."
				
				#exit the program loop
				break
		
		#debug
		print "[PSnif]\t\tExited."
		
		#debug
		print "[Psnif]\tReturning..."
		
		#kill the thread
		return

	def start_packetsniffer(self):
		self.running = 1
		
		#debug
		print "[Main]\tStart button pressed."
	
	def pause_packetsniffer(self):
		self.running = 2
		
		#debug
		print "[Main]\tPause button pressed."
		
	def end_packetsniffer(self):
		self.running = 0

		#debug
		print "[Main]\tStop button pressed."
    
		
#create root frame
root = Tk()

#set up main thread and packet sniffer thread
main_thread = _MasterThread(root)

root.mainloop()