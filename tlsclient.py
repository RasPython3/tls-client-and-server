from tlscommon import *
import secrets

class Client:
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