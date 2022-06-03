#!/usr/bin/python3

import os
import time
from pwn import *
import argparse
import nmap

parser = argparse.ArgumentParser()
requiredNamed = parser.add_argument_group('Required named arguments')
parser.add_argument("-n","--nmap", help="Scanner with nmap")
requiredNamed.add_argument("-i","--ip", help="Option to put the ip", required=True)
parser.add_argument("-f","--fuzz", help="Usage fuzz")
parser.parse_args()
args=parser.parse_args()

def portsEnumeration():	

	try:
		nm = nmap.PortScanner()
		nm.scan(args.ip)
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
			print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))
	except:
		print ("error")

if __name__=="__main__":

	portsEnumeration()
