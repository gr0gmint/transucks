from twisted.internet.protocol import Factory,Protocol
from twisted.internet import reactor
import socket
import sys


SO_ORIGINAL_DST = 80
if __name__ == "__main__":
  try:
    socks_server_ip = argv[1]
    socks_server_port = argv[2]
  except:
    print "sucks <socks-server-ip> <socks-server-port>"  
    exit()


def sint(x):
  sum = 0
  for byte in x:
    sum = (sum << 8) + ord(byte)
  return sum

class TransSOCKS(Protocol):
  def connectionMade(self):
    self.dst_info = self.transport.socket.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST,16)
    self.dst_port = sint(self.dst_info[2:4])
    self.dst_addr = socket.inet_ntoa(self.dst_info[4:8])
  def dataReceived(self, data):
    print self.dst_addr, " ", self.dst_port
    
factory = Factory()
factory.protocol = TransSOCKS
reactor.listenTCP(1337,factory)
reactor.run()
