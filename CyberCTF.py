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
parser.add_argument("-n","--nmap", help="Scanner with nmap")
requiredNamed.add_argument("-i","--ip", help="Option to put the ip", required=True)
parser.add_argument("-f","--fuzz", help="Usage fuzz")
parser.parse_args()
args=parser.parse_args()
list=[]


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
		for host in nm.all_hosts():
			print('----------------------------------------------------')
			print('Host : %s (%s)' % (host, nm[host].hostname()))
			print('State : %s' % nm[host].state())
		for proto in nm[host].all_protocols():
			print('----------')
			print('Protocol : %s' % proto)
			lport = nm[host][proto].keys()
			sorted(lport)
		for port in lport:
			print ('port: %s --> %s   | ' % (port, nm[host][proto][port]['state']),end=" ")
			print (scanVulnerability(port))
	except:
		print ("[/!\] CAN'T CONNECT WITH THE HOST [/!\]")
		exit(1)

def scanVulnerability(port): #need finish this
	match port:
		case 21:
			return "[!] FTP PORT: VERIFY ANONYMOUS ACCESS [!]"
		case 80 | 8080 | 443:
			return "[!] HTTP/S PORT:  SHOULD FUZZING (SUBDOMAIN's AND DIRECTORY's) & VISUALIZE VERSIONS [!]"
		case 23:
			return "[!] TELNET PORT:  -- EXECUTE --> \"nc -vn %s 23\" [!] " % (args.ip)
		case 25 | 465 | 587:
			return "[!] SMTP PORT: [!]"
		case 110 | 995:
			return "[!] POP3 PORT:  [!]" 
		case 135 | 593:
			return "[!] MSRPC PORT: [!]"
		case 139 | 445:
			return "[!] SMB PORT: ¡TRY TO GET CREDENTIALS! -- TOOLS: \n\t [*] SMBCLIENT: smbclient  -U 'username[%passwd]' -L <IP> [!] \n\t [*] SMBMAP: smbmap -u 'username' -p 'password' -H <IP> [-P <PORT>] "
		case 143 | 993:
			return "[!] IMAP PORT: [!]"
		case 161 | 162 | 10161 | 10162:
			return "[!] SNMP PORT: -- EXECUTE --> \"snmpbulkwalk -c <public | private> -v 2c %s \" [!]" % (args.ip)

if __name__=="__main__":
	banner()
	portsEnumerationTCP()
