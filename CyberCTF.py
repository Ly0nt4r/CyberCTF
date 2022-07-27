#!/usr/bin/python3

import os
import time
from pwn import *
import argparse
import nmap
from tqdm import tqdm
import urllib.request
import os.path
from progress.bar import Bar
import requests
import threading 
import keyboard



parser = argparse.ArgumentParser()
requiredNamed = parser.add_argument_group('Required named arguments')
parser.add_argument("-wd", "--WDir", help="Fuzzing Wordlists Directory")
parser.add_argument("-I","--interactive", help="Mode interactive (Automatic scanning)", action="store_false")
requiredNamed.add_argument("-i","--ip", help="Option to put the ip", required=True)
parser.add_argument("-f","--fuzz", help="Usage fuzz", action='store_true')
parser.parse_args()
args=parser.parse_args()

class style(): # colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    ITALIC='\x1B[3m'
    RES='\x1B[0m'
    BOLD='\033[1m'

def banner():

	print (style.RED+'''
	 ██████╗██╗   ██╗██████╗ ███████╗██████╗      ██████╗████████╗███████╗
	██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗    ██╔════╝╚══██╔══╝██╔════╝
	██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝    ██║        ██║   █████╗
	██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗    ██║        ██║   ██╔══╝
	╚██████╗   ██║   ██████╔╝███████╗██║  ██║    ╚██████╗   ██║   ██║
	 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝     ╚═════╝   ╚═╝   ╚═╝
	'''+style.YELLOW+'''				author: @Lyont4R | CyberCTF v1.0.1
	'''+style.BLUE+'''----------------------------------------------------------------------
	'''+style.RESET)


def portsEnumerationUDP():
	try:

		print ("===================================================================")
		print (style.MAGENTA+style.BOLD+"                     Ports Discovery - UDP                         "+style.RESET)
		print ("===================================================================")


		nmU= nmap.PortScanner()
		nmU.scan(hosts=args.ip, arguments="-sU --open -n --top-ports 300 -T5")
		
		for host in nm.all_hosts():
			print('----------------------------------------------------')
			print(style.GREEN+'Host: '+ style.RESET + '%s (%s)' % (host, nmU[host].hostname()))
			print(style.GREEN+'State: '+ style.RESET + '%s' % nmU[host].state())
		for proto in nmU[host].all_protocols():
			print('----------')
			print(style.GREEN+'Protocol:'+ style.RESET + ' %s' % proto)
			lport = nmU[host][proto].keys()
			sorted(lport)
		for port in lport:
			print (style.GREEN+'port: '+ style.RESET + '%s\t'+style.GREEN+'state: '+ style.RESET + ' %s' % (port, nmU[host][proto][port]['state']))
	except:
		print ("NO UDP ports open")

def portsEnumerationTCP():

	try:

		print ("===================================================================")
		print (style.MAGENTA+style.BOLD+"                      Ports Discovery - TCP                        "+style.RESET)
		print ("===================================================================")


		p2=log.progress(style.CYAN+"Scanning ports..."+style.RESET)
		nm = nmap.PortScanner()
		nm.scan(hosts=args.ip, arguments="-Pn -n --min-rate 5000 --open")
		for host in nm.all_hosts(): # for hosts
			print('----------------------------------------------------')
			print(style.GREEN+'Host: '+ style.RESET + '%s (%s)' % (host, nm[host].hostname()))
			print(style.GREEN+'State: '+ style.RESET + '%s' % nm[host].state())
		for proto in nm[host].all_protocols(): # for protocols 
			print('----------')
			print(style.GREEN+'Protocol:'+ style.RESET + ' %s' % proto)
			lport = nm[host][proto].keys()
			sorted(lport)
		for port in lport: # for ports
			print (style.GREEN+'port: '+ style.RESET + style.RESET + '%s --> %s ' % (port,nm[host][proto][port]['state']))
		p2.status("Finished")
	except:
		p2=log.progress("Failed scan")
		exit(1)


def fuzzing():
	print("")
	file = 'directory-list-2.3-medium.txt'
	exist=False

	print ("===================================================================")
	print (style.MAGENTA+style.BOLD+"                     	  FUZZING 		                   "+style.RESET)
	print ("===================================================================")
 
	existPath=os.path.exists(file)

	p3=log.progress(style.CYAN+"Fuzzing Web"+style.RESET)
	p3.status("In Process")

	
	try:
		fileSize= open(file, 'r')
		size=len(fileSize.readlines())
		fileSize.close()

		bar = Bar('Processing: ', max=size)

		#	p3.status ("Wordlists not found's")
		#	exit(1)
		p6=log.progress(style.CYAN+"Testing directory with"+style.RESET)
		with open(file) as files:
			try:
				for line in files:
					p6.status(args.ip+"/"+line) #printing result
					time.sleep(.2)
					r = requests.get("http://"+args.ip+"/"+line) #request
					if r.status_code == 200:
						print ("["+style.YELLOW  + "FOUND" + style.RESET+"]"+style.GREEN+ " %s -->" % (r.status_code) + style.RESET+ " %s " % (line))
					elif r.status_code == 301 or r.status_code == 302:
						print ("["+style.YELLOW  + "FOUND" + style.RESET+"]"+style.BLUE+ " %s --> " % (r.status_code) + style.RESET+ " %s " % (line))
					elif r.status_code == 500:
						print ("["+style.YELLOW  + "FOUND" + style.RESET+"]"+style.YELLOW+ " %s -->" % (r.status_code) + style.RESET+ " %s " % (line))
			except KeyboardInterrupt:
    				pass

				#bar.next()
			#bar.finish()
		p3.status("Success")
	except:
		p3.status("Failed")
		print ("[*]   ¿Port(s) HTTP(s) is active?")
		print ("[*]   ¿PATH or NAME wordlists is correct?")

if __name__=="__main__":
	banner()
	portsEnumerationTCP()
	portsEnumerationUDP()
	fuzzing()
