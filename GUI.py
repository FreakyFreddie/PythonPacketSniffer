#!/usr/bin/python
#GUI for Python Packet Sniffer

#idea - check buttons as filters?
#TKinter tutorial: http://www.tutorialspoint.com/python/python_gui_programming.htm

#import Tkinter GUI library
from Tkinter import *
from ttk import *

#create root frame
root = Tk()

#ButtonFrame for Start, Pause and Stop
ButtonFrame = Frame(root)

#ButtonFrame can expand horizontally (X)
ButtonFrame.pack(fill=X, expand=1, pady=3)

#ButtonFrame is the master widget
StartButtonClass = Button(ButtonFrame, text="Start")
PauseButtonClass = Button(ButtonFrame, text="Pause")
StopButtonClass = Button(ButtonFrame, text="Stop")

StartButtonClass.pack(side=LEFT, expand=1, padx=3)
PauseButtonClass.pack(side=LEFT, expand=1, padx=3)
StopButtonClass.pack(side=LEFT, expand=1, padx=3)

#TextFrame for Text widget
TextFrame = Frame(root)

#TextFrame can expand horizontally (X)
TextFrame.pack(fill=X, expand=1, pady=3)


root.mainloop()

class _Startbutton(Button):

class _Pausebutton(Button):

class _Stopbutton(Button):

class _Output(Frame):
  
    def __init__(self, parent):
        Frame.__init__(self, parent)   
         
        self.parent = parent
        self.initUI()

        
    def initUI(self):
      
        self.parent.title("Review")
        self.pack(fill=BOTH, expand=True)
        
        frame1 = Frame(self)
        frame1.pack(fill=X)
        
        lbl1 = Label(frame1, text="Title", width=6)
        lbl1.pack(side=LEFT, padx=5, pady=5)           
       
        entry1 = Entry(frame1)
        entry1.pack(fill=X, padx=5, expand=True)
        
        frame2 = Frame(self)
        frame2.pack(fill=X)
        
        lbl2 = Label(frame2, text="Author", width=6)
        lbl2.pack(side=LEFT, padx=5, pady=5)        

        entry2 = Entry(frame2)
        entry2.pack(fill=X, padx=5, expand=True)
        
        frame3 = Frame(self)
        frame3.pack(fill=BOTH, expand=True)
        
        lbl3 = Label(frame3, text="Review", width=6)
        lbl3.pack(side=LEFT, anchor=N, padx=5, pady=5)        

        txt = Text(frame3)
        txt.pack(fill=BOTH, pady=5, padx=5, expand=True)           
              

def main():
	#create root window
    root = Tk()
	
	#width x length + xposition + yposition
    root.geometry("300x300+300+300")
	
	#create buttons & output frame
    StartButtonClass = _StartButton(root)
	PauseButtonClass = _PauseButton(root)
	StopButtonClass = _StopButton(root)
	OutputClass = _Output(root)
	
    root.mainloop()  


if __name__ == '__main__':
    main() 
	
#CREATE TEXT BOX TO PRINT
from Tkinter import *

root = Tk()
S = Scrollbar(root)
T = Text(root, height=4, width=50)
S.pack(side=RIGHT, fill=Y)
T.pack(side=LEFT, fill=Y)
S.config(command=T.yview)
T.config(yscrollcommand=S.set)
quote = """HAMLET: To be, or not to be--that is the question:
Whether 'tis nobler in the mind to suffer
The slings and arrows of outrageous fortune
Or to take arms against a sea of troubles
And by opposing end them. To die, to sleep--
No more--and by a sleep to say we end
The heartache, and the thousand natural shocks
That flesh is heir to. 'Tis a consummation
Devoutly to be wished."""
T.insert(END, quote)
mainloop(  )