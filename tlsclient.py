from tlscommon import *
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
        result = []
        while True:
            data = self.sock.recv(4096)
            if len(data) == 0:
                break
            result.extend([*data])
        return result
    
    def connect(self, address:str, port:int):
        if self.isconnected:
            raise RuntimeError("Already connected")
        self.sock = socket.create_connection((address, port))
        self._isconnected = True
    
    def handshake(self):
        self.check_connected()

        client_random = self.random["client"] = gen_random(32)

        client_hello = TLSClientHelloFrame()
        client_hello.random = client_random
        client_hello.extensions.append(TLSExtension(43, [2, 3, 4]))

        self.send(client_hello.get_binary())

        server_hello = self.recv()
        print(server_hello)

        try:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()
        except:
            pass

    

class TLSClientHelloFrame(TLSHandshakeFrame):
    def __init__(self):
        super().__init__()
        self.handshake_type = 1 # Handshake

        self.random = None # FIXME
        self.cipher_suites = [] # FIXME
        self.extensions = [] # FIXME
        pass
    
    @classmethod
    def parse(cls, data:list):
        pass

    def get_binary(self):
        if not isinstance(self.random, (list, tuple)) or len(self.random) != 32:
            raise RuntimeError("ClientHello random is not set or a wrong value")
        
        result = []

        # Protocol Version
        result.extend([3, 3]) # 0x0303

        # random
        result.extend(self.random)

        # legacy session id ( ignore )
        result.extend([1, 0])

        # cipher suites
        result.extend(int_to_list(len(self.cipher_suites) * 2, 2))
        for cipher_suite in self.cipher_suites:
            result.extend(cipher_suite)

        # legacy compression methods
        result.extend([1, 0])

        result.extend(self.get_extensions_binary())

        return self.set_handshake_header(result)