from tls.common import *
from tls.client import Client

def main():
    client = Client()
    client.connect("127.0.0.1", 50000)
    client.handshake()
    return
    for i in range(len(client_hello_binary)):
        if i % 16 == 15 or i+1 == len(client_hello_binary):
            print("{:0>2x}".format(client_hello_binary[i]))
        else:
            print("{:0>2x}".format(client_hello_binary[i]), end=" ")

if __name__ == "__main__":
    main()