#!/usr/bin/python
#GUI for Python Packet Sniffer

#idea - check buttons as filters?
#TKinter tutorial: http://www.tutorialspoint.com/python/python_gui_programming.htm

#import Tkinter GUI library
from Tkinter import *
from ttk import *

#Import threading module since we need to run our packet sniffer in a different thread
#threading module is more powerfull than thread module
import threading

#create root frame
root = Tk()

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
StartButtonClass = Button(ButtonFrame, text="Start", command=togglepacketsniffer())
PauseButtonClass = Button(ButtonFrame, text="Pause")
StopButtonClass = Button(ButtonFrame, text="Stop")

StartButtonClass.pack(side=LEFT, expand=1, padx=3)
PauseButtonClass.pack(side=LEFT, expand=1, padx=3)
StopButtonClass.pack(side=LEFT, expand=1, padx=3)

#TextFrame for Text widget
TextFrame = Frame(root)

#TextFrame can expand horizontally (X)
TextFrame.pack(fill=X, expand=1, pady=3)

FrameText = Text(TextFrame)
FrameText.pack(fill=X, expand=1, pady=3)
FrameText.insert(END,"Hello ")
FrameText.insert(END,"Olivier")
FrameText.insert(END,"\n")
FrameText.insert(END,"Goodbye")
FrameText.insert(END,"olivier")

#add scroll barr
TextScroller = Scrollbar(FrameText)
TextScroller.pack(side=RIGHT, fill=Y)
TextScroller.config(command=FrameText.yview)

root.mainloop()

def startpacketsniffer():
	#if no thread running already threading.currentThread() Returns the number of thread objects in the caller's thread control.
	#start new thread: function with arguments
	thread.start_new_thread ( function, args[, kwargs] )
	sock = create_socket()
	while True:
		pack = extract_packet(sock)