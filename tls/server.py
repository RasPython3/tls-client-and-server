from .common import *

from . import ext

from .server import *

from .base import *


class TLSServerHelloFrame(TLSHandshakeFrame):
    def __init__(self):
        super().__init__()
        self.type_id = 0x02 # Server Hello

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

class TLSEncryptedExtensionsFrame(TLSHandshakeFrame):
    def __init__(self):
        super().__init__()
        self.type_id = 0x08
        self.extensions = []

    @classmethod
    def parse(cls, data:list):
        if len(data) < 2:
            raise ValueError("Too small data")
        
        result = cls()
        
        extensions_length = data[0] * 0x100 + data[1]

        index = 2
        k = 0
        while k < extensions_length:
            extension_length = data[index+k+2] * 0x100 + data[index+k+3]

            if k + extension_length + 4 > extensions_length:
                raise RuntimeError("Illegal extension length")

            result.extensions.append(ext.TLSExtension.parse(data[index+k:index+k+extension_length+4], ext.MODE["encrypted_extensions"]))

            k += extension_length + 4

        return result

    def get_binary(self):
        result = []

        result.extend(self.get_extensions_binary())

        return result

class TLSCertificateFrame(TLSHandshakeFrame):
    def __init__(self, context, certs):
        super().__init__()
        self.type_id = 0x0b
        self.context = context
        self.certificates = certs

    @classmethod
    def parse(cls, data: list):
        if len(data) == 0 or len(data) < 4 + data[0]:
            raise RuntimeError("Illegal length")

        context = data[1:data[0]+1]

        index = data[0] + 1

        certs_length_left = data[index] * 0x10000 + data[index+1] * 0x100 + data[index+2]

        if len(data) != 4 + data[0] + certs_length_left:
            raise RuntimeError("Illegal length")

        index += 3

        cert_entries = []
        while certs_length_left > 0:
            if certs_length_left < 3:
                raise RuntimeError("Illegal length")
            cert_data_length = data[index] * 0x10000 + data[index+1] * 0x100 + data[index+2]

            index += 3
            cert_data = crypto.load_der_x509_certificate(bytes(data[index:index+cert_data_length]))
            index += cert_data_length
            certs_length_left -= cert_data_length + 3

            if certs_length_left < 2:
                raise RuntimeError("Illegal length")
            cert_extensions_length = data[index] * 0x100 + data[index+1]

            if certs_length_left - 2 < cert_extensions_length:
                raise RuntimeError("Illegal length")

            k = 0
            cert_extensions = []
            while k < cert_extensions_length:
                extension_length = data[index+k+2] * 0x100 + data[index+k+3]

                if k + extension_length + 4 > cert_extensions_length:
                    raise RuntimeError("Illegal extension length")

                cert_extensions.append(ext.TLSExtension.parse(data[index+k:index+k+extension_length+4], ext.MODE["certificate"]))

                k += extension_length + 4
            
            cert_entries.append(CertificateEntry(
                cert_data,
                cert_extensions
            ))

            certs_length_left -= cert_extensions_length + 2
            index += cert_extensions_length + 2

        if certs_length_left < 0:
            raise RuntimeError("Illegal length")

        return cls(context, cert_entries)

    def get_binary(self):
        cert_binary = []

        for entry in self.certificates:
            cert_binary.extend(entry.get_binary())

        return [len(self.context)] + self.context + int_to_list(len(cert_binary), 3) + cert_binary

class TLSCertificateVerifyFrame(TLSHandshakeFrame):
    def __init__(self, signature_algorithm, signature:list):
        super().__init__()
        self.type_id = 0x0f
        self.signature_scheme = signature_algorithm
        self.signature = signature

    @classmethod
    def parse(cls, data: list):
        if len(data) < 4:
            raise RuntimeError("Illegal length")

        sig_scheme = SignatureScheme.parse(data[:2])

        sig_length = data[2] * 0x100 + data[3]

        if len(data) != sig_length + 4:
            raise RuntimeError("Illegal length")

        signature = data[4:]

        return cls(sig_scheme, signature)

    def get_binary(self):
        return self.signature_scheme.get_binary() + int_to_list(len(self.signature), 2) + self.signature