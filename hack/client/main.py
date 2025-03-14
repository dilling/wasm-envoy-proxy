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

            transport = THttpClient.THttpClient('http://envoy:10000')
            transport.setCustomHeaders(headers)
            transport = TTransport.TBufferedTransport(transport)
            protocol = TBinaryProtocol.TBinaryProtocol(transport)
            client = PotatoService.Client(protocol)
            
            transport.open()
            spud = client.getSpud()
            print(spud)
            transport.close()
        except Exception as e:
            print(e)

        time.sleep(5)

if __name__ == '__main__':
    main()
