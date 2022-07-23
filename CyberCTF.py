#!/usr/bin/python3

import os
import time
from pwn import *
import argparse
import nmap
from tqdm import tqdm
import urllib.request


parser = argparse.ArgumentParser()
requiredNamed = parser.add_argument_group('Required named arguments')
parser.add_argument("-wd", "--WDir", help="Fuzzing Wordlists Directory")
parser.add_argument("-ws","--WSub", help="Fuzzing Wordlists Subdomains")
requiredNamed.add_argument("-i","--ip", help="Option to put the ip", required=True)
parser.add_argument("-f","--fuzz", help="Usage fuzz", action='store_true')
parser.parse_args()
args=parser.parse_args()

def banner():

	print ('''
	 ██████╗██╗   ██╗██████╗ ███████╗██████╗      ██████╗████████╗███████╗
	██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗    ██╔════╝╚══██╔══╝██╔════╝
	██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝    ██║        ██║   █████╗
	██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗    ██║        ██║   ██╔══╝
	╚██████╗   ██║   ██████╔╝███████╗██║  ██║    ╚██████╗   ██║   ██║
	 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝     ╚═════╝   ╚═╝   ╚═╝
					author: @Lyont4R | CyberCTF v1.0.1
	----------------------------------------------------------------------
	''')


def portsEnumerationUDP():
	try:

		print ("===================================================================")
		print ("                     Ports Discovery - UDP                         ")
		print ("===================================================================")


		nmU= nmap.PortScanner()
		nmU.scan(hosts=args.ip, arguments="-sU --open -n --top-ports 300 -T5")
		
		for host in nm.all_hosts():
			print('----------------------------------------------------')
			print('Host : %s (%s)' % (host, nmU[host].hostname()))
			print('State : %s' % nmU[host].state())
		for proto in nmU[host].all_protocols():
			print('----------')
			print('Protocol : %s' % proto)
			lport = nmU[host][proto].keys()
			sorted(lport)
		for port in lport:
			print ('port: %s\tstate: %s' % (port, nmU[host][proto][port]['state']))
	except:
		print ("NO UDP ports open")

def portsEnumerationTCP():

	try:

		print ("===================================================================")
		print ("                      Ports Discovery - TCP                        ")
		print ("===================================================================")


		p2=log.progress("Scanning ports...")
		nm = nmap.PortScanner()
		nm.scan(hosts=args.ip, arguments="-Pn -n --min-rate 5000 --open")
		for host in nm.all_hosts(): # for hosts
			print('----------------------------------------------------')
			print('Host : %s (%s)' % (host, nm[host].hostname()))
			print('State : %s' % nm[host].state())
		for proto in nm[host].all_protocols(): # for protocols 
			print('----------')
			print('Protocol : %s' % proto)
			lport = nm[host][proto].keys()
			sorted(lport)
		for port in lport: # for ports
			print ('port: %s --> %s ' % (port, nm[host][proto][port]['state']))
		p2.status("Finished")
	except:
		p2=log.progress("Failed scan")
		exit(1)


def fuzzing():
	print("")
	file = 'directory-list-2.3-medium.txt'
	exist=False

	print ("===================================================================")
	print ("                     	  FUZZING 		                   ")
	print ("===================================================================")

#	for root, dirs, files in os.walk('/usr/share/'):  
#		if file in files:
#			exist=True
#			print (os.path.dirname(file))

	p3=log.progress("Fuzzing Web")
	p3.status("In Process")
	
	try:
		if args.WDir == None:
			p3.status ("Wordlists not found's")
			print ('\x1b[1;37;41m'+"You must add wordlists"+ '\x1b[0m'+ '\x1b[1;32;40m' +" ::  -wd <Wordlists.txt> :: "+ '\x1b[0m')
		p6=log.progress("Testing directory with")
		with open(args.WDir) as file:
			for line in file:
				p6.status(line)
		
		p3.status("Success")
	except:
		p3.status("Failed")
		print ("[*]   ¿Port(s) HTTP(s) is active?")
		print ("[*]   ¿PATH or NAME wordlists is correct?")

if __name__=="__main__":
	banner()
	portsEnumerationTCP()
#	portsEnumerationUDP()
	fuzzing()
