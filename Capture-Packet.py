import sys, pygame
import test
from pygame.locals import *
import time
import subprocess
import os
import glob
import socket
os.environ["SDL_FBDEV"] = "/dev/fb1"
os.environ["SDL_MOUSEDEV"] = "/dev/input/touchscreen"
os.environ["SDL_MOUSEDRV"] = "TSLIB"
pygame.init()


#define function that checks for mouse location
def on_click():
        click_pos = (pygame.mouse.get_pos() [0], pygame.mouse.get_pos() [1])
        #check to see if exit has been pressed
        if 500 <= click_pos[0] <= 640 and 5 <= click_pos[1] <=150:
                button(0)
        #now check to see if play was pressed
        if 20 <= click_pos[0] <= 160 and 5 <= click_pos[1] <=150:
                button(1)
        #now check to see if stop  was pressed
        if 260 <= click_pos[0] <= 400 and 5 <= click_pos[1] <=150:
                button(2)


#define action on pressing buttons
def button(number):
        if number == 0:    #specific script when exiting
                sys.exit()

        if number == 1:
                sock = test.create_socket()
                while number == 1:
                        pack = test.extract_packet(sock)
                        #pack.Length etc. to get values
                        print str(pack.Length)
                        print str(pack.DataLinkHeader.SourceMAC)
                        print str(pack.DataLinkHeader.DestinationMAC)
                refresh_menu_screen()

        if number == 2:
                serial.write('\x03')
                refresh_menu_screen()

def refresh_menu_screen():
#set up the fixed items on the menu
        screen.fill(white) #change the colours if needed
        font=pygame.font.Font(None,24)
        title_font=pygame.font.Font(None,34)
        station_font=pygame.font.Font(None,20)
        label=title_font.render("Sniffy", 1, (red))
        label2=font.render("Wireshark by Dennis/Joachim", 1, (green))
        screen.blit(label,(105, 260))
        screen.blit(label2,(88, 300))
        play=pygame.image.load("play.tiff")
        pause=pygame.image.load("pause.tiff")
        exit=pygame.image.load("exit.tiff")
        # draw the main elements on the screen
        screen.blit(play,(20,5))
        screen.blit(pause,(260,5))
        screen.blit(exit,(500,5))
        pygame.draw.rect(screen, green, (0,0,640,480),3)
        pygame.display.flip()

def main():
        while 1:
                for event in pygame.event.get():                        
                        if event.type == pygame.MOUSEBUTTONDOWN:
                                pos = (pygame.mouse.get_pos() [0], pygame.mouse.get_pos() [1])
                                pygame.draw.circle(screen, white, pos, 2, 0) #for debugging purposes - adds a small dot where the screen is pressed
                                on_click()

#ensure there is always a safe way to end the program if the touch screen fails

                        if event.type == KEYDOWN:
                                if event.key == K_ESCAPE:
                                        sys.exit()
        time.sleep(0.2)
        pygame.display.update()


#################### EVERTHING HAS NOW BEEN DEFINED ###########################

#set size of the screen
size = width, height = 640, 480
screen = pygame.display.set_mode(size)

#define colours
blue = 26, 0, 255
cream = 254, 255, 25
black = 0, 0, 0
white = 255, 255, 255
yellow = 255, 255, 0
red = 189, 17, 67
green = 118, 169, 40
refresh_menu_screen()  #refresh the menu interface 
main() #check for key presses and start emergency exit
station_name()

