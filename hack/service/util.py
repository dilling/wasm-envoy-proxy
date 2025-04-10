from thrift.Thrift import TProcessor
from thrift.server.THttpServer import ResponseException, BaseHTTPServer


def send_empty_response(handler: BaseHTTPServer.BaseHTTPRequestHandler):
    handler.send_response(400)

class ProcessorWithCatch(TProcessor):
    def __init__(self, processor: TProcessor):
        self._processor = processor

    def process(self, iprot, oprot):
        try:
            return self._processor.process(iprot, oprot)
        except EOFError:
            raise ResponseException(send_empty_response)
        except Exception:
            raise
