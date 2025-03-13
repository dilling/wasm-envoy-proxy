from gen.potatoService import PotatoService

from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol

from thrift.server import TServer

class PotatoServiceHandler(PotatoService.Iface):
    def getSpud(self):
        return "🥔"


if __name__ == '__main__':
    handler = PotatoServiceHandler()
    processor = PotatoService.Processor(handler)
    transport = TSocket.TServerSocket(host='127.0.0.1', port=9090)
    tfactory = TTransport.TBufferedTransportFactory()
    pfactory = TBinaryProtocol.TBinaryProtocolFactory()

    server = TServer.TSimpleServer(processor, transport, tfactory, pfactory)

    print('Starting the server...')
    server.serve()
    print('done.')