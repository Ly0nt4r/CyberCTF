#!/usr/bin/python3

import os
import time
from pwn import *
import argparse
import nmap
import colorama
from colorama import Fore, Style

parser = argparse.ArgumentParser()
requiredNamed = parser.add_argument_group('Required named arguments')
parser.add_argument("-w","--wordlists", help="Wordlist's Fuzzing")
requiredNamed.add_argument("-i","--ip", help="Option to put the ip", required=True)
parser.add_argument("-f","--fuzz", help="Usage fuzz", action='store_true')
parser.add_argument("-v","--verbose", help="Verbose", action='store_true')
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
		nmU= nmap.PortScanner()
		nmU.scan(hosts=args.ip, arguments="-sU -n --top-ports 300 -T5")
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
		exit(1)

def portsEnumerationTCP():

	try:
		p2=log.progress("Scanning ports...")
		nm = nmap.PortScanner() 
		nm.scan(hosts=args.ip, arguments="-Pn -n --min-rate 5000 ")
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
			print ('port: %s --> %s   | ' % (port, nm[host][proto][port]['state']),end=" ")
			print (scanVulnerability(port))
	except:
		p2=log.progress("Failed scan")
		exit(1)

def scanVulnerability(port): 
	##
	## Ports with commons vulnerability
	##
	match port:
		case 21:
			return "[!] FTP PORT: VERIFY ANONYMOUS ACCESS [!]"
		case 80 | 8080 | 443:
			return "[!] HTTP/S PORT:  SHOULD FUZZING (SUBDOMAIN's AND DIRECTORY's) & VISUALIZE VERSIONS [!]"
		case 23:
			return "[!] TELNET PORT:  -- EXECUTE --> \"nc -vn %s 23\" [!] " % (args.ip)
		case 25 | 465 | 587:
			return "[!] SMTP PORT: -- EXECUTE --> \"nc -vn %s <port> \" [!]" % (args.ip)
		case 135 | 593:
			return "[!] MSRPC PORT: YOU SHOULD TRY RPCDUMP \n[*] rpcdump [-p port] %s" % (args.ip)
		case 139 | 445:
			return "[!] SMB PORT: ¡TRY TO GET CREDENTIALS (you can see without it)! -- TOOLS: \n\t [*] SMBCLIENT: smbclient  -U 'username[%passwd]' -L <IP> [!] \n\t [*] SMBMAP: smbmap -u 'username' -p 'password' -H <IP> [-P <PORT>] "
		case 161 | 162 | 10161 | 10162:
			return "[!] SNMP PORT: -- EXECUTE --> \"snmpbulkwalk -c <public | private> -v 2c %s \" [!]" % (args.ip)

def fuzzing():
	print("---------------------------------------------------------------------------")
	p3=log.progress("Init fuzzing web")

	try:
		with open(args.wordlists,'r') as file:
			line=file.readlines()
			if args.verbose == True:
				print(line)	
		file.close()			
	except:
		print (args.wordlists)
		if args.wordlists == None:
			p3.status("You must add wordlists -->  -w < PATH/wordlistsExample.txt >")
		p3.status("Failed fuzz... ¿Port(s) HTTP(s) is active?")

if __name__=="__main__":
	banner()
	portsEnumerationTCP()
	if args.fuzz == True:
		fuzzing()		
			
