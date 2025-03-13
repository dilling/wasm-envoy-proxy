from gen.potatoService import PotatoService

from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
import time

def main():
    transport = TSocket.TSocket('localhost', 9090)
    transport = TTransport.TBufferedTransport(transport)
    protocol = TBinaryProtocol.TBinaryProtocol(transport)
    client = PotatoService.Client(protocol)

    while True:
        try:
            transport.open()
            spud = client.getSpud()
            print(spud)
            transport.close()
        except Exception as e:
            print(e)

        time.sleep(5)

if __name__ == '__main__':
    main()
