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
		ButtonFrame = Frame(root, borderwidth=1, relief=RAISED)

		#ButtonFrame can expand horizontally (X)
		ButtonFrame.pack(fill=X, expand=1)

		#ButtonFrame is the master widget
		#create label for frame
		LabelFrame = Frame(ButtonFrame)
		LabelFrame.pack(fill=X, expand=1, pady=3)

		FrameLabel = Label(LabelFrame, text="Control Panel")
		FrameLabel.pack(side=LEFT, expand=1, padx=3)

		#create buttons
		StartButtonClass = Button(ButtonFrame, text="Start")
		PauseButtonClass = Button(ButtonFrame, text="Pause")
		StopButtonClass = Button(ButtonFrame, text="Stop", command=endCommand)

		StartButtonClass.pack(side=LEFT, expand=1, padx=3)
		PauseButtonClass.pack(side=LEFT, expand=1, padx=3)
		StopButtonClass.pack(side=LEFT, expand=1, padx=3)

		#TextFrame for Text widget
		TextFrame = Frame(root)

		#TextFrame can expand horizontally (X)
		TextFrame.pack(fill=X, expand=1, pady=3)

		FrameText = Text(TextFrame)
		FrameText.pack(fill=X, expand=1, pady=3)

		#add scroll barr
		TextScroller = Scrollbar(FrameText)
		TextScroller.pack(side=RIGHT, fill=Y)
		TextScroller.config(command=FrameText.yview)
		
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

			print msg

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

		#create the actual thread
		self.PacketSnifferThread = threading.Thread(target=self.packet_sniffer_thread)

		#launch the thread
		self.PacketSnifferThread.start()

		#create a socket with create_socket() from Capture-Packet
		self.sock = create_socket()

		#start the programloop
		self.call_programloop()

    def call_programloop(self):
        #process queue, include pausechecker
		#this function empties the queue
        self.gui.process_queue(self.running)
		
		#check exit condition
        if self.running == 0:
			#close the socket
			self.sock.close()
			
			#exit the program
            sys.exit(1)
		
		#test the queue for contents every 100 milliseconds
		#checks stop button after the queue
        self.root.after(100, self.call_programloop)

    def packet_sniffer_thread(self):
		#run the program until stop/pause
        while self.running == 1:
			#extract a packet from the socket
			self.pack = extract_packet(self.sock)

			#add the packet object to the queue
			self.queue.put(pack)

	def start_packetsniffer(self):
		self.running = 1
	
	def pause_packetsniffer(self):
		self.running = 2
		
    def end_packetsniffer(self):
        self.running = 0

#create root frame
root = Tk()

#set up main thread and packet sniffer thread
ps_thread = _MasterThread(root)

root.mainloop()