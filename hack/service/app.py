from gen.potatoService import PotatoService

from thrift.protocol import TBinaryProtocol
from thrift.server import THttpServer

from util import ProcessorWithCatch

class PotatoServiceHandler(PotatoService.Iface):
    def getSpud(self):
        return "🥔"

if __name__ == '__main__':
    handler = PotatoServiceHandler()
    processor = PotatoService.Processor(handler)
    pfactory = TBinaryProtocol.TBinaryProtocolFactory()

    server = THttpServer.THttpServer(
        ProcessorWithCatch(processor),
        ('', 8080),
        pfactory
    )

    print('Starting the server...')
    server.serve()
