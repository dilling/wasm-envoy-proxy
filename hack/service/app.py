from gen.potatoService import PotatoService

from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
from thrift.server import THttpServer

class PotatoServiceHandler(PotatoService.Iface):
    def getSpud(self):
        return "🥔"

if __name__ == '__main__':
    handler = PotatoServiceHandler()
    processor = PotatoService.Processor(handler)
    tfactory = TTransport.TBufferedTransportFactory()
    pfactory = TBinaryProtocol.TBinaryProtocolFactory()

    server = THttpServer.THttpServer(
        processor,
        ('', 9090),
        pfactory
    )

    print('Starting the server...')
    server.serve()
