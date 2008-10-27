from twisted.internet.protocol import Factory,Protocol,ClientCreator
from twisted.protocols.socks import SOCKSv4,SOCKSv4Outgoing
from twisted.internet import reactor
import socks_twisted
from socks_twisted import SOCKSClient,SOCKSClientFactory
import socket
import sys
import time

SO_ORIGINAL_DST = 80
if __name__ == "__main__":
  try:
    socks_host = sys.argv[1]
    socks_port = int(sys.argv[2])
    socks_type = socks_twisted.PROXY_TYPE_SOCKS4
  except:
    print "sucks <socks-server-ip> <socks-server-port>"  
    exit()


def sint(x):
  sum = 0
  for byte in x:
    sum = (sum << 8) + ord(byte)
  return sum


class TransSOCKS(Protocol):
  def __init__(self):
    self.otherfactory = SOCKSTransporterFactory
    print type(self.otherfactory)
    self.buf = ''
    self.established=False
    self.other = None
  def connectionMade(self):
    self.dst_info = self.transport.socket.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST,16)
    self.dst_port = sint(self.dst_info[2:4])
    self.dst_addr = socket.inet_ntoa(self.dst_info[4:8])
    factory = self.otherfactory([self.dst_addr,self.dst_port], proxytype=socks_twisted.PROXY_TYPE_SOCKS4)
    factory.setOther(self)
    reactor.connectTCP(socks_host,socks_port,factory)
  def dataReceived(self, data):
        if self.established:
            try:
                self.other.transport.write(self.buf+data)
                self.buf=""
            except:
                self.other.transport.loseConnection()
        else:
            self.buf += data

class SOCKSTransporter(SOCKSClient):
    def dataReceived(self,data):
        SOCKSClient.dataReceived(self,data)
        if self.established and self.buf:
            try:
                self.other.transport.write(self.buf)
            except:
                pass
            self.buf=''
    def connectionEstablished(self):
        self.other.other = self
        self.other.established = True
        self.other.dataReceived('')
    def connectionLost(self,reason):
        self.other.transport.loseConnection()
            
class SOCKSTransporterFactory(SOCKSClientFactory):
    def setOther(self,other):
        self.other = other
    def buildProtocol(self,addr):
        protocol = SOCKSTransporter(self.destpair,self.proxyconf)
        protocol.other = self.other
        return protocol

factory = Factory()
factory.protocol = TransSOCKS
reactor.listenTCP(1337,factory)
reactor.run()
