from .common import *
import secrets
import socket

class Client:
    def __init__(self, *, version=0x0304):
        if version != 0x0304:
            raise RuntimeError("Only TLS 1.3 is supported")
        self.version = version
        self.sock = None
        self._isconnected = False
        self.random = {"client": None, "server": None}
        self.cache = []
    
    @property
    def isconnected(self):
        return self._isconnected
    
    def check_connected(self):
        if not self.isconnected:
            raise RuntimeError("Client is not connected to the server yet.")
    
    def send(self, data:list):
        self.check_connected()
        return self.sock.send(bytes(data))

    def recv(self):
        self.check_connected()

        tls_type = -1
        tls_length = -1
        data = [*self.cache]
        self.cache = []
        
        buffer_size = 5 # TLS header
        while tls_length < 0 or len(data) < 5 + tls_length:
            data.extend(self.sock.recv(buffer_size))

            if tls_length < 0 and len(data) >= 5:
                tls_type = data[0]
                tls_length = data[3] * 0xff + data[4]
                buffer_size = tls_length - len(data) + 5
        
        if len(data) > 5 + tls_length:
            self.cache.extend(data[tls_length+5:])

        result = TLSRecordFrame.parse(data[:tls_length+5])

        print_tree(result)
        print()

        return result
    
    def connect(self, address:str, port:int):
        if self.isconnected:
            raise RuntimeError("Already connected")
        self.sock = socket.create_connection((address, port))
        self._isconnected = True
    
    def handshake(self):
        self.check_connected()

        client_random = self.random["client"] = gen_random(32)

        self.private_key = crypto.PrivateKey.generate(crypto.X25519)
        self.public_key = crypto.PublicKey.from_private(self.private_key)

        self.shared_key = None

        client_hello = TLSClientHelloFrame()
        client_hello.random = client_random
        client_hello.cipher_suites.append(TLSCipherSuite(0x1301))
        client_hello.extensions.append(TLSExtension(43, [2, 3, 4])) # supported versions
        client_hello.extensions.append(TLSExtension(13, [0, 2, 4, 3])) # signature algorithms
        client_hello.extensions.append(TLSExtension(10, [0, 2, 0, 0x1d])) # supported groups ecdhe x25195
        client_hello.extensions.append(TLSExtension(51, [0, 36, 0, 0x1d, 0, 32] + self.public_key.value)) # key share

        self.send(
            TLSRecordFrame(
                TLSHandshakeFrame(
                    client_hello
                )
            ).get_binary())

        server_hello = self.recv()

        try:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()
        except:
            pass
