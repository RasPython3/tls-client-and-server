from ...common import TLSVersion, CipherSuite

from ..base import TLSHandshakeFrame

from ... import ext

from ...utils import int_to_list


class TLSClientHelloFrame(TLSHandshakeFrame):
    def __init__(self, version:TLSVersion=TLSVersion("1.2"), random:list=None, cipher_suites:list=[], extensions:list=[]):
        super().__init__()
        self.type_id = 0x01 # Client Hello

        self.tls_version = version # TLS 1.2
        self.random = random
        self.legacy_session_id = None
        self.cipher_suites = cipher_suites
        self.legacy_compression_methods = []
        self.extensions = extensions
    
    @classmethod
    def parse(cls, data:list):
        if len(data) < 53:
            raise ValueError("Too small data")
        
        result = cls()
        
        result.tls_version = TLSVersion(data[0] * 0x100 + data[1])

        result.random = data[2:34]

        index = 34

        result.legacy_session_id = data[35:35+data[index]]

        index += data[index] + 1

        for k in range(0, data[index] * 0x100 + data[index+1], 2):
            result.cipher_suites.append(CipherSuite.parse(data[index+k+2:index+k+4]))

        index += 2 + len(result.cipher_suites) * 2

        for k in range(0, data[index]):
            result.legacy_compression_methods.append(data[index+k+1])

        index += data[index] + 1

        extensions_length = data[index] * 0x100 + data[index+1]

        k = 2
        while k < extensions_length + 2:
            extension_length = data[index+k+2] * 0x100 + data[index+k+3]

            if k + extension_length + 4 > extensions_length + 2:
                raise RuntimeError("Illegal extension length")

            result.extensions.append(ext.TLSExtension.parse(data[index+k:index+k+extension_length+4], ext.MODE["client_hello"]))

            k += extension_length + 4

        return result

    def get_binary(self):
        if not isinstance(self.random, (list, tuple)) or len(self.random) != 32:
            raise RuntimeError("ClientHello random is not set or a wrong value")
        
        result = []

        # Protocol Version
        result.extend(int_to_list(self.tls_version.value, 2)) # 0x0303

        # random
        result.extend(self.random)

        # legacy session id ( ignore )
        result.extend([0])

        # cipher suites
        result.extend(int_to_list(len(self.cipher_suites) * 2, 2))
        for cipher_suite in self.cipher_suites:
            result.extend(int_to_list(cipher_suite.type_id, 2))

        # legacy compression methods
        result.extend([1, 0])

        result.extend(self.get_extensions_binary())

        return result
