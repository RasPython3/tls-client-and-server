from .common import BaseTLSFrame, TLSVersion
from .utils import int_to_list

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



class TLSChildFrame(BaseTLSFrame):
    def __init__(self, data=None):
        super().__init__()
        self.type_id = None
        self.data = data

class TLSParentFrame(TLSChildFrame):
    def __init__(self, child=None, child_id=None):
        super().__init__()
        self.child = child
        if isinstance(child, TLSChildFrame) and child_id == None:
            self.child_id = child.type_id
        else:
            self.child_id = None

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
    def __init__(self):
        super().__init__()
        self.type_id = 20

    @classmethod
    def parse(cls, data:list):
        if len(data) != 1 or data[0] != 1:
            raise RuntimeError("Illegal ChangeCipherSpec")
        return cls()

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
        self.tls_version = TLSVersion("1.2") # TLS 1.2

    @classmethod
    def parse(cls, data:list):
        if len(data) < 4:
            raise RuntimeError("Illegal length")

        if len(data) - 4 != data[1] * 0x10000 + data[2] * 0x100 + data[3]:
            raise RuntimeError("Illegal length")

        child_type = data[0]

        child = TLSChildFrame(data[4:])
        child.type_id = child_type

        return cls(child)

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
    def __init__(self):
        super().__init__()
        self.type_id = 23

    pass

class TLSTLSHeartbeatFrame(TLSChildFrame):
    def __init__(self):
        super().__init__()
        self.type_id = 24

    pass
