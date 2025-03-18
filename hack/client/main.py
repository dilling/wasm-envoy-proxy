from gen.potatoService import PotatoService

from thrift.transport import THttpClient
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol
import time
import requests

def get_token():
    response = requests.post('http://auth:8080/token')
    response.raise_for_status()
    return response.json().get('access_token')

def main():
    while True:
        print("Sending Request...")
        try:
            token = get_token()
            headers = {'Authorization': f'Bearer {token}'}

            http_transport = THttpClient.THttpClient('http://envoy:10000')
            http_transport.setCustomHeaders(headers)
            transport = TTransport.TBufferedTransport(http_transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = PotatoService.Client(protocol)
            
            transport.open()
            error = None
            try:
                spud = client.getSpud()
            except Exception as e:
                error = e
            finally:
                transport.close()

            if http_transport.code == 401:
                raise Exception("Unauthorized")
            
            if error is not None:
                raise error

            print(spud)

        except Exception as e:
            print("The spud was a dud: " + str(e))

        time.sleep(5)

if __name__ == '__main__':
    main()
