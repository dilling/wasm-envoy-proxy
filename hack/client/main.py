from gen.potatoService import PotatoService

from thrift.transport import THttpClient
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
import time

def main():
    transport = THttpClient.THttpClient('http://service:9090')
    transport = TTransport.TBufferedTransport(transport)
    protocol = TBinaryProtocol.TBinaryProtocol(transport)
    client = PotatoService.Client(protocol)

    while True:
        print("Sending Request...")
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
