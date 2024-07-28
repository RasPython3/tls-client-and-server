from ...common import TLSVersion, CipherSuite

from ..base import TLSHandshakeFrame

from ... import ext

from ...utils import int_to_list

class TLSHelloRetryRequestFrame(TLSHandshakeFrame):
    def __init__(self):
        super().__init__()
        self.type_id = 0x06 # Hello Retry Request

        self.tls_version = 0x0303 # TLS 1.2
        self.random = None
        self.legacy_session_id = None
        self.cipher_suite = None
        self.legacy_compression_method = 0
        self.extensions = []
    
    @classmethod
    def parse(cls, data:list):
        if len(data) < 40:
            raise ValueError("Too small data")
        
        result = cls()
        
        result.tls_version = data[0] * 0x100 + data[1]

        result.random = data[2:34]

        index = 34

        result.legacy_session_id = data[35:35+data[index]]

        index += data[index] + 1

        result.cipher_suite = TLSCipherSuite.parse(data[index:index+2])

        index += 2

        result.legacy_compression_method = data[index]

        index += 1

        extensions_length = data[index] * 0x100 + data[index+1]

        index += 2
        k = 0
        while k < extensions_length:
            extension_length = data[index+k+2] * 0x100 + data[index+k+3]

            if k + extension_length + 4 > extensions_length:
                raise RuntimeError("Illegal extension length")

            result.extensions.append(ext.TLSExtension.parse(data[index+k:index+k+extension_length+4], ext.MODE["server_hello"]))

            k += extension_length + 4

        return result

    def get_binary(self):
        if not isinstance(self.random, (list, tuple)) or len(self.random) != 32:
            raise RuntimeError("ServerHello random is not set or a wrong value")
        
        result = []

        # Protocol Version
        result.extend([3, 3]) # 0x0303

        # random
        result.extend(self.random)

        # legacy session id ( ignore )
        result.extend([0])

        # cipher suite
        result.extend(int_to_list(self.cipher_suite.type_id, 2))

        # legacy compression methods
        result.extend([0])

        result.extend(self.get_extensions_binary())

        return result

