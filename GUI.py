#!/usr/bin/python
#GUI for Python Packet Sniffer

#idea - check buttons as filters?
#TKinter tutorial: http://www.tutorialspoint.com/python/python_gui_programming.htm

#Sys library for exit()
import sys

#import Tkinter GUI library
from Tkinter import *
from ttk import *

#Import threading module since we need to run our packet sniffer in a different thread
#threading module is more powerfull than thread module
import threading

#import Queue for Capture-Packet module thread
import Queue

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
		self.ButtonFrame.pack(fill=X, expand=1)

		#ButtonFrame is the master widget
		#create label for frame
		self.LabelFrame = Frame(self.ButtonFrame)
		self.LabelFrame.pack(fill=X, expand=1, pady=3)

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
		self.TextFrame.pack(fill=X, expand=1, pady=3)

		self.FrameText = Text(self.TextFrame)
		self.FrameText.pack(fill=X, expand=1, pady=3)

		#add scroll barr
		self.TextScroller = Scrollbar(self.FrameText)
		self.TextScroller.pack(side=RIGHT, fill=Y)
		self.TextScroller.config(command=self.FrameText.yview)
		
	#process the current queue
	def process_queue(self, pausecheck):	
		while self.queue.qsize() > 0:

			#extract a packet from the queue
			pack = self.queue.get(0)

			#format the packet for printing
			formatted_packet = "Packet length: " + str(pack.Length)

			#if pause has been clicked, don't print anything
			#else update the TextFrame's FrameText with the packet info
			if pausecheck != 2:
				self.FrameText.insert(END, formatted_packet)

class _MasterThread:
	#we launch the sub process and the main thread
	def __init__(self, root):
		#use the root window we created
		self.root = root

		#Create the queue (FIFO, NOT LIFO)
		#Queue size defaults to 0 --> Queue can grow infinitly
		self.queue = Queue.Queue()

		#Set up the GUI
		#we pass the queue to the GUI to update the text
		self.gui = _InterfaceGUI(root, self.queue, self.start_packetsniffer, self.pause_packetsniffer, self.end_packetsniffer)
		
		#start value
		self.running = 1
		
		#create the actual thread
		self.PacketSnifferThread = threading.Thread(target=self.packet_sniffer_thread)

		#launch the thread
		self.PacketSnifferThread.start()

		#check if thread is running
		print str(self.PacketSnifferThread.isAlive())
		
		#create a socket with create_socket() from Capture-Packet
		self.sock = create_socket()
		
		#debug
		print "Socket created: " + str(self.sock)
		
		#declare the packet
		self.pack = None
		
		#debug
		print "Packet created: " + str(self.pack)

		#start the programloop
		self.call_programloop()

	def call_programloop(self):
		#debug
		print "Processing " + str(self.queue.qsize()) + " items from queueu"
		
		#process queue, include pausechecker
		#this function empties the queue
		self.gui.process_queue(self.running)

		#check exit condition
		if self.running == 0:
			#close the socket
			#self.sock.close()
			
			#debug
			print "Exiting..."
			
			#exit the program
			sys.exit(1)
		
		#test the queue for contents every 1000 milliseconds
		#checks stop button after the queue
		self.root.after(1000, self.call_programloop)

	def packet_sniffer_thread(self):
		#debug
		print str(self.running)

		#run the program until stop/pause
		while self.running == 1:
			#extract a packet from the socket
			self.pack = extract_packet(self.sock)

			#debug
			print str(self.pack.Length)
			
			#add the packet object to the queue
			self.queue.put(self.pack)
			
			#debug
			print "Packet added to queue"

	def start_packetsniffer(self):
		self.running = 1
		
		#debug
		print "Start button pressed"
	
	def pause_packetsniffer(self):
		self.running = 2
		
		#debug
		print "Pause button pressed"
		
	def end_packetsniffer(self):
		self.running = 0
		
		#debug
		print "Stop button pressed"

#create root frame
root = Tk()

#set up main thread and packet sniffer thread
ps_thread = _MasterThread(root)

root.mainloop()