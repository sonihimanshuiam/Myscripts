#!/usr/bin/python3

from socket import *
import optparse
from threading import *

def connScan(tgtHost, tgtPort):
	try:
		sock=socket(AF_INET, SOCK_STREAM)
		sock.connect((tgtHost,tgtPort))
		print (" %d/tcp open" %(tgtPort))
	except:
		print ("%d/tcp closed" %(tgtPort))
	finally:
		sock.close()

def portscan(tgtHost, tgtPorts):
	try:
		tgtIP = gethostbyname(tgtHost)
	except:
		print ("Unknown host %s"%(tgtHost))
	try:
		tgtName = gethostbyaddr(tgtIP)
		print("Scan result for: " + tgtName[0])
	except:
		print("Scan result fort: " +tgtIP)

	setdefaulttimeout(1)
	for tgtPort in tgtPorts:
		t = Thread(target=connScan, args=(tgtHost , int(tgtPort)))	
		t.start()


def main():

	parser = optparse.OptionParser('Usage of program' + '-H <Target Host> -p <Target port>')
	parser.add_option('-H',dest='tgtHost',type='string',help='Specify Target host')
	parser.add_option('-p',dest='tgtPort',type='string',help='Specify Target Ports saperated by comma')
	(options,args) = parser.parse_args()
	tgtHost=options.tgtHost
	tgtPorts=str(options.tgtPort).split(',')
	if (tgtHost==None) | (tgtPorts[0]==None):
		print (parser.usage)
		exit(0)
	portscan(tgtHost,tgtPorts)

if __name__=='__main__':
		main()

