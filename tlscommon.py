import secrets
import crypto

from tlsutils import *
from tlsextension import *


class NetworkFrame(object):
    def __init__(self):
        pass
    
    @classmethod
    def parse(cls, data):
        return cls()
    
    def get_binary(self):
        return []


class BaseTLSFrame(NetworkFrame):
    def __init__(self):
        pass

    def set_tls_header(self, data:list):
        result = [self.tls_record_type, 3, 1] + int_to_list(len(data), 2) + data
        return result

    def get_extensions_binary(self):
        extension_binaries = []

        for extension in self.extensions:
            extension_binaries.extend(extension.get_binary())

        return int_to_list(len(extension_binaries), 2) + extension_binaries




class TLSCipherSuite(object):
    cipher_suite_types = {
        0x1301: "TLS_AES_128_GCM_SHA256",
        0x1302: "TLS_AES_256_GCM_SHA384",
        0x1303: "TLS_CHACHA20_POLY1305_SHA256",
        0x1304: "TLS_AES_128_CCM_SHA256",
        0x1305: "TLS_AES_128_CCM_8_SHA256",
    }
    def __init__(self, type_id:int=0):
        self.type_id = type_id # null
    
    @classmethod
    def parse(cls, data: list):
        if len(data) != 2:
            raise ValueError("Wrong size data")

        type_id = data[0] * 0x100 + data[1]

        result = cls()
        result.type_id = type_id

        return result
    
    def get_binary(self):
        return int_to_list(self.type_id, 2)



class TLSParentFrame(BaseTLSFrame):
    def __init__(self, child=None):
        super().__init__()
        self.child = child

class TLSChildFrame(BaseTLSFrame):
    def __init__(self, data=None):
        super().__init__()
        self.data = data

class TLSUnknownFrame(TLSChildFrame):
    pass

class TLSRecordFrame(TLSParentFrame):
    def __init__(self, child=None):
        super().__init__(child)
        self.tls_version = 0x0301 # TLS 1.0

    @classmethod
    def parse(cls, data:list):
        if len(data) < 5:
            raise RuntimeError("Illegal length")

        if len(data) - 5 != data[3] * 0x100 + data[4]:
            raise RuntimeError("Illegal length")

        if data[0] == 20:
            child_cls = TLSChangeCipherSpecFrame
        elif data[0] == 21:
            child_cls = TLSAlertFrame
        elif data[0] == 22:
            child_cls = TLSHandshakeFrame
        elif data[0] == 23:
            child_cls = TLSApplicationDataFrame
        elif data[0] == 24:
            child_cls = TLSHeartbeatFrame
        else:
            child_cls = TLSUnknownFrame

        result = cls(child_cls.parse(data[5:]))

        result.tls_version = data[1] * 0x100 + data[2]

        return result

    def get_binary(self):
        result = [self.child.type_id]
        
        child_binary = self.child.get_binary()

        result.extend(int_to_list(self.tls_version, 2))
        result.extend(int_to_list(len(child_binary), 2))
        result.extend(child_binary)

        return result

class TLSChangeCipherSpecFrame(TLSChildFrame):
    @classmethod
    def parse(cls, data:list):
        if len(data) != 1 or data[0] != 1:
            raise RuntimeError("Illegal ChangeCipherSpec")
        return cls(None)

    def get_binary(self):
        return [0x01]

class TLSAlertFrame(TLSChildFrame):
    def __init__(self, level, description):
        super().__init__(None)
        self.level = level
        self.description = description
        self.levels = {
            1: "warning",
            2: "fatal"
        }
        self.descriptions = {
            0: "close_notify",
            10: "unexpected_message",
            20: "bad_record_mac",
            21: "decryption_failed_RESERVED",
            22: "record_overflow",
            30: "decompression_failure_RESERVED",
            40: "handshake_failure",
            41: "no_certificate_RESERVED",
            42: "bad_certificate",
            43: "unsupported_certificate",
            44: "certificate_revoked",
            45: "certificate_expired",
            46: "certificate_unknown",
            47: "illegal_parameter",
            48: "unknown_ca",
            49: "access_denied",
            50: "decode_error",
            51: "decrypt_error",
            60: "export_restriction_RESERVED",
            70: "protocol_version",
            71: "insufficient_security",
            80: "internal_error",
            86: "inappropriate_fallback",
            90: "user_canceled",
            100: "no_renegotiation_RESERVED",
            109: "missing_extension",
            110: "unsupported_extension",
            111: "certificate_unobtainable_RESERVED",
            112: "unrecognized_name",
            113: "bad_certificate_status_response",
            114: "bad_certificate_hash_value_RESERVED",
            115: "unknown_psk_identity",
            116: "certificate_required",
            120: "no_application_protocol"
        }

    def __str__(self):
        if self.level in self.levels:
            level_str = self.levels[self.level]
        else:
            level_str = "unknown"

        if self.description in self.descriptions:
            description_str = self.descriptions[self.description]
        else:
            description_str = "unknown"

        return "<{} level={} description={}>".format(
            self.__class__.__name__,
            level_str,
            description_str)

    @classmethod
    def parse(cls, data:list):
        if len(data) != 2:
            raise RuntimeError("Illegal length")
        return cls(data[0], data[1])

    def get_binary(self):
        return [self.level, self.description]

class TLSHandshakeFrame(TLSParentFrame):
    def __init__(self, child=None):
        super().__init__(child)
        self.type_id = 22
        self.tls_version = 0x0303 # TLS 1.2

    @classmethod
    def parse(cls, data:list):
        if len(data) < 4:
            raise RuntimeError("Illegal length")

        if len(data) - 4 != data[1] * 0x10000 + data[2] * 0x100 + data[3]:
            raise RuntimeError("Illegal length")

        child_type = data[0]

        if child_type == 1:
            child_cls = TLSClientHelloFrame
        elif child_type == 2:
            child_cls = TLSServerHelloFrame
        else:
            child_cls = TLSUnknownFrame

        return cls(child_cls.parse(data[4:]))

    def get_binary(self):
        result = [self.child.type_id]
        
        child_binary = self.child.get_binary()

        result.extend(int_to_list(len(child_binary), 3))
        result.extend(child_binary)

        return result

    def set_handshake_header(self, data:list):
        result = [self.handshake_type] + int_to_list(len(data), 3) + data
        return self.set_tls_header(result)

class TLSApplicationDataFrame(TLSParentFrame):
    pass

class TLSTLSHeartbeatFrame(TLSChildFrame):
    pass



class TLSClientHelloFrame(TLSHandshakeFrame):
    def __init__(self):
        super().__init__()
        self.type_id = 0x01 # Client Hello

        self.tls_version = 0x0303 # TLS 1.2
        self.random = None
        self.legacy_session_id = None
        self.cipher_suites = []
        self.legacy_compression_methods = []
        self.extensions = []
    
    @classmethod
    def parse(cls, data:list):
        if len(data) < 53:
            raise ValueError("Too small data")
        
        result = cls()
        
        result.tls_version = data[0] * 0x100 + data[1]

        result.random = data[2:34]

        index = 34

        result.legacy_session_id = data[35:35+data[index]]

        index += data[index] + 1

        for k in range(0, data[index] * 0x100 + data[index+1], 2):
            result.cipher_suites.append(TLSCipherSuite.parse(data[index+k+2:index+k+4]))

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

            result.extensions.append(TLSExtension.parse(data[index+k:index+k+extension_length+4]))

            k += extension_length + 4

        return result

    def get_binary(self):
        if not isinstance(self.random, (list, tuple)) or len(self.random) != 32:
            raise RuntimeError("ClientHello random is not set or a wrong value")
        
        result = []

        # Protocol Version
        result.extend([3, 3]) # 0x0303

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

            result.extensions.append(TLSExtension.parse(data[index+k:index+k+extension_length+4]))

            k += extension_length + 4

        return result

    def get_binary(self):
        if not isinstance(self.random, (list, tuple)) or len(self.random) != 32:
            raise RuntimeError("ClientHello random is not set or a wrong value")
        
        result = []

        # Protocol Version
        result.extend([3, 3]) # 0x0303

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

        return self.set_handshake_header(result)
