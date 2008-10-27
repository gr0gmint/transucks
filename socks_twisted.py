"""
Ported from:
SocksiPy - Python SOCKS module.
Version 1.00

Copyright 2006 Dan-Haim. All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of Dan Haim nor the names of his contributors may be used
   to endorse or promote products derived from this software without specific
   prior written permission.
   
THIS SOFTWARE IS PROVIDED BY DAN HAIM "AS IS" AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
EVENT SHALL DAN HAIM OR HIS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA
OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMANGE.


"""

import socket
import struct
from twisted.internet.protocol import Protocol,ClientFactory

PROXY_TYPE_SOCKS4 = 1
PROXY_TYPE_SOCKS5 = 2
PROXY_TYPE_HTTP = 3

_defaultproxy = None
_orgsocket = socket.socket



class ProxyError(Exception):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return repr(self.value)

class GeneralProxyError(ProxyError):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return repr(self.value)

class Socks5AuthError(ProxyError):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return repr(self.value)

class Socks5Error(ProxyError):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return repr(self.value)

class Socks4Error(ProxyError):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return repr(self.value)

class HTTPError(ProxyError):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return repr(self.value)

_generalerrors = ("success",
		   "invalid data",
		   "not connected",
		   "not available",
		   "bad proxy type",
		   "bad input")

_socks5errors = ("succeeded",
		  "general SOCKS server failure",
		  "connection not allowed by ruleset",
		  "Network unreachable",
		  "Host unreachable",
		  "Connection refused",
		  "TTL expired",
		  "Command not supported",
		  "Address type not supported",
		  "Unknown error")

_socks5autherrors = ("succeeded",
		      "authentication is required",
		      "all offered authentication methods were rejected",
		      "unknown username or invalid password",
		      "unknown error")

_socks4errors = ("request granted",
		  "request rejected or failed",
		  "request rejected because SOCKS server cannot connect to identd on the client",
		  "request rejected because the client program and identd report different user-ids",
		  "unknown error")


class SOCKSClient(Protocol):
	def __init__(self, destpair,proxyconf):
		self.destpair = destpair
		self.__proxy = proxyconf
	
	def setproxy(self,proxytype=None,addr=None,port=None,rdns=True,username=None,password=None):
		"""setproxy(proxytype, addr[, port[, rdns[, username[, password]]]])
		Sets the proxy to be used.
		proxytype -	The type of the proxy to be used. Three types
				are supported: PROXY_TYPE_SOCKS4 (including socks4a),
				PROXY_TYPE_SOCKS5 and PROXY_TYPE_HTTP
		addr -		The address of the server (IP or DNS).
		port -		The port of the server. Defaults to 1080 for SOCKS
				servers and 8080 for HTTP proxy servers.
		rdns -		Should DNS queries be preformed on the remote side
				(rather than the local side). The default is True.
				Note: This has no effect with SOCKS4 servers.
		username -	Username to authenticate with to the server.
				The default is no authentication.
		password -	Password to authenticate with to the server.
				Only relevant when username is also provided.
		"""
		self.__proxy = (proxytype,addr,port,rdns,username,password)
	
	def __negotiatesocks5(self,destaddr,destport):
		"""__negotiatesocks5(self,destaddr,destport)
		Negotiates a connection through a SOCKS5 server.
		"""
		# First we'll send the authentication packages we support.
		if (self.__proxy[4]!=None) and (self.__proxy[5]!=None):
			# The username/password details were supplied to the
			# setproxy method so we support the USERNAME/PASSWORD
			# authentication (in addition to the standard none).
			self.transport.write("\x05\x02\x00\x02")
		else:
			# No username/password were entered, therefore we
			# only support connections with no authentication.
			self.transport.write("\x05\x01\x00")
		# We'll receive the server's response to determine which
		# method was selected
		chosenauth = self.checkbuf(2)
		if not chosenauth:
			self.cocommand = ("MoreBytes",2)
			chosenauth = yield
			self.cocommand = ""
		if chosenauth[0] != "\x05":
			self.transport.loseConnection()
			raise GeneralProxyError((1,_generalerrors[1]))
		# Check the chosen authentication method
		if chosenauth[1] == "\x00":
			pass
		elif chosenauth[1] == "\x02":
			# Okay, we need to perform a basic username/password
			# authentication.
			self.transport.write("\x01" + chr(len(self.__proxy[4])) + self.__proxy[4] + chr(len(self.proxy[5])) + self.__proxy[5])
			authstat = self.checkbuf(8)
			if not authstat:
				self.cocommand = ("MoreBytes",8)
				authstat = yield
				self.cocommand = ""
			if authstat[0] != "\x01":
				# Bad response
				self.transport.loseConnection()
				raise GeneralProxyError((1,_generalerrors[1]))
			if authstat[1] != "\x00":
				# Authentication failed
				self.transport.loseConnection()
				raise Socks5AuthError,((3,_socks5autherrors[3]))
			# Authentication succeeded
		else:
			# Reaching here is always bad
			self.transport.loseConnection()
			if chosenauth[1] == "\xFF":
				raise Socks5AuthError((2,_socks5autherrors[2]))
			else:
				raise GeneralProxyError((1,_generalerrors[1]))
		# Now we can request the actual connection
		req = "\x05\x01\x00"
		# If the given destination address is an IP address, we'll
		# use the IPv4 address request even if remote resolving was specified.
		try:
			ipaddr = socket.inet_aton(destaddr)
			req = req + "\x01" + ipaddr
		except socket.error:
			# Well it's not an IP number,  so it's probably a DNS name.
			if self.__proxy[3]==True:
				# Resolve remotely
				ipaddr = None
				req = req + "\x03" + chr(len(destaddr)) + destaddr
			else:
				# Resolve locally
				ipaddr = socket.inet_aton(socket.gethostbyname(destaddr))
				req = req + "\x01" + ipaddr
		req = req + struct.pack(">H",destport)
		self.transport.write(req)
		# Get the response
		resp = self.checkbuf(4)
		if not resp:
			self.cocommand = ("MoreBytes",4)
			resp = yield
			self.cocommand = ""
		if resp[0] != "\x05":
			self.transport.loseConnection()
			raise GeneralProxyError((1,_generalerrors[1]))
		elif resp[1] != "\x00":
			# Connection failed
			self.transport.loseConnection()
			if ord(resp[1])<=8:
				raise Socks5Error(ord(resp[1]),_generalerrors[ord(resp[1])])
			else:
				raise Socks5Error(9,_generalerrors[9])
		# Get the bound address/port
		elif resp[3] == "\x01":
			boundaddr = self.checkbuf(4)
			if not boundaddr:
				self.cocommand = ("MoreBytes",4)
				boundaddr = yield
				self.cocommand = ""
		elif resp[3] == "\x03":
			resp2 = self.checkbuf(1)
			if not resp2:
				self.cocommand = ("MoreBytes",1)
				resp2 = yield
				self.cocommand = ""
			resp = resp + resp2
			boundaddr = self.checkbuf(resp[4])
			if not boundaddr:
				self.cocommand = ("MoreBytes",resp[4])
				boundaddr = yield
				self.cocommand = ""
		else:
			self.transport.loseConnection()
			raise GeneralProxyError((1,_generalerrors[1]))
		recv = self.checkbuf(2)
		if not recv:
			self.cocommand=("MoreBytes",2)
			recv = yield
			self.cocommand=""
		print "Got the last 2 bytes: ", len(recv)
		boundport = struct.unpack(">H",recv)[0]
		self.__proxysockname = (boundaddr,boundport)
		if ipaddr != None:
			self.__proxypeername = (socket.inet_ntoa(ipaddr),destport)
		else:
			self.__proxypeername = (destaddr,destport)
		self.established = True
		self.connectionEstablished()
	def getproxysockname(self):
		"""getsockname() -> address info
		Returns the bound IP address and port number at the proxy.
		"""
		return self.__proxysockname

	def getpeername(self):
		"""getpeername() -> address info
		Returns the IP address and port number of the destination
		machine (note: getproxypeername returns the proxy)
		"""
		return self.__proxypeername

	def checkbuf(self, num=None):
		answer = ''
		if num == None and len(self.buf) > 0:
			answer = self.buf
			self.buf = ""
		elif num and len(self.buf) >= num:
			answer = self.buf[:num]
			self.buf = self.buf[num:]
		return answer


	def __negotiatesocks4(self,destaddr,destport):
		"""__negotiatesocks4(self,destaddr,destport)
		Negotiates a connection through a SOCKS4 server.
		"""
		# Check if the destination address provided is an IP address
		rmtrslv = False
		try:
			ipaddr = socket.inet_aton(destaddr) # make asynchronous
		except socket.error:
			# It's a DNS name. Check where it should be resolved.
			if self.__proxy[3]==True:
				ipaddr = "\x00\x00\x00\x01"
				rmtrslv = True
			else:
				ipaddr = socket.inet_aton(socket.gethostbyname(destaddr))
		# Construct the request packet
		req = "\x04\x01" + struct.pack(">H",destport) + ipaddr
		# The username parameter is considered userid for SOCKS4
		if self.__proxy[4] != None:
			req = req + self.__proxy[4]
		req = req + "\x00"
		# DNS name if remote resolving is required
		# NOTE: This is actually an extension to the SOCKS4 protocol
		# called SOCKS4A and may not be supported in all cases.
		if rmtrslv==True:
			req = req + destaddr + "\x00"
		self.transport.write(req)
		# Get the response from the server
		resp = self.checkbuf(8)
		if not resp:
			self.cocommand = ("MoreBytes",8)
			resp = yield
			self.cocommand = ""
		if resp[0] != "\x00":
			# Bad data
			self.transport.loseConnection()
			raise GeneralProxyError((1,_generalerrors[1]))
		if resp[1] != "\x5A":
			# Server returned an error
			self.transport.loseConnection()
			if ord(resp[1]) in (91,92,93):
				self.transport.loseConnection()
				raise Socks4Error((ord(resp[1]),_socks4errors[ord(resp[1])-90]))
			else:
				raise Socks4Error((94,_socks4errors[4]))
		# Get the bound address/port
		self.__proxysockname = (socket.inet_ntoa(resp[4:]),struct.unpack(">H",resp[2:4])[0])
		if rmtrslv != None:
			self.__proxypeername = (socket.inet_ntoa(ipaddr),destport)
		else:
			self.__proxypeername = (destaddr,destport)
		self.established = True
		self.connectionEstablished()
		
		
	def __negotiatehttp(self,destaddr,destport):
		"""__negotiatehttp(self,destaddr,destport)
		Negotiates a connection through an HTTP server.
		"""
		# If we need to resolve locally, we do this now
		if self.__proxy[3] == False:
			addr = socket.gethostbyname(destaddr)    # from __future__ import better_asynchronous_way_to_do_this
		else:
			addr = destaddr
		self.transport.write("CONNECT " + addr + ":" + str(destport) + " HTTP/1.1\r\n" + "Host: " + destaddr + "\r\n\r\n")
		# We read the response until we get the string "\r\n\r\n"
		resp = self.checkbuf()
		while resp.find("\r\n\r\n")==-1:
			self.cocommand = "MoreBytes"
			resp2 = yield
			self.cocommand = ""
			resp += resp2
		# We just need the first line to check if the connection
		# was successful
		statusline = resp.splitlines()[0].split(" ",2)
		if statusline[0] not in ("HTTP/1.0","HTTP/1.1"):
			self.transport.loseConnection()
			raise GeneralProxyError((1,_generalerrors[1]))
		try:
			statuscode = int(statusline[1])
		except ValueError:
			self.transport.loseConnection()
			raise GeneralProxyError((1,_generalerrors[1]))
		if statuscode != 200:
			self.transport.loseConnection()
			raise HTTPError((statuscode,statusline[2]))
		self.__proxysockname = ("0.0.0.0",0)
		self.__proxypeername = (addr,destport)

		self.established = True
		self.connectionEstablished()
		
	def dataReceived(self,data):
		    if self.cocommand == "MoreBytes":
			    tosend = self.buf + data
			    self.buf = ""
			    try:
				    self.coroutine.send(tosend)
			    except:
				    pass
		    elif type(self.cocommand) == tuple and self.cocommand[0] == "MoreBytes":
			    bytesneeded = self.cocommand[1]
			    self.buf += data
			    if len(self.buf) >= bytesneeded:
				    try:
					    self.coroutine.send(self.buf[:bytesneeded])
				    except:
					    pass
				    self.buf = self.buf[bytesneeded:]
		    else:
			    self.buf += data
	        
	def connectionMade(self):
		"""
		Connects to the specified destination through a proxy.
		destpar - A tuple of the IP/DNS address and the port number.
		(identical to socket's connect).
		To select the proxy server use setproxy().
		"""
		self.buf=""
		self.established = False
		self.cocommand = ""
		# Do a minimal input check first
		if (type(self.destpair) in (list,tuple)==False) or (len(self.destpair)<2) or (type(self.destpair[0])!=str) or (type(self.destpair[1])!=int):
			raise GeneralProxyError((5,_generalerrors[5]))
		if self.__proxy[0] == PROXY_TYPE_SOCKS5:
			if self.__proxy[2] != None:
				portnum = self.__proxy[2]
			else:
				portnum = 1080
			print "Trying SOCKSv5"
			self.coroutine = self.__negotiatesocks5(self.destpair[0],self.destpair[1])
		elif self.__proxy[0] == PROXY_TYPE_SOCKS4:
			if self.__proxy[2] != None:
				portnum = self.__proxy[2]
			else:
				portnum = 1080
			print "Trying SOCKSv4"
			self.coroutine = self.__negotiatesocks4(self.destpair[0],self.destpair[1])
		elif self.__proxy[0] == PROXY_TYPE_HTTP:
			if self.__proxy[2] != None:
				portnum = self.__proxy[2]
			else:
				portnum = 8080
			print "Trying HTTP"
			self.coroutine = __negotiatehttp(self.destpair[0],self.destpair[1])
		else:
			raise GeneralProxyError((4,_generalerrors[4]))
		self.coroutine.next()
	def connectionEstablished(self):
		pass
class SOCKSClientFactory(ClientFactory):
	def __init__(self, destpair, proxytype=None,addr=None,port=None,rdns=True,username=None,password=None,protocol=None):
		"""
		@type destpair = [list|tuple]
		"""
		self.destpair = destpair
		self.proxyconf = [proxytype,addr,port,rdns,username,password]
	def buildProtocol(self, addr):
		return SOCKSClient(self.destpair,self.proxyconf)
