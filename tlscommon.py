import secrets

def int_to_list(intValue, length):
    result = []
    for i in range(length):
        result.append((intValue // (0xff ** (length - i - 1))) % 0xff)
    return result

def gen_random(length: int):
    return [int(i) for i in secrets.token_bytes(length)]

class NetworkFrame(object):
    def __init__(self):
        pass

class BaseTLSFrame(NetworkFrame):
    def __init__(self):
        self.extensions = []
    
    def set_tls_header(self, data:list):
        result = [self.tls_record_type, 3, 1] + int_to_list(len(data), 2) + data
        return result
    
    def get_extensions_binary(self):
        extension_binaries = []

        for extension in self.extensions:
            extension_binaries.extend(extension.get_binary())
        
        return int_to_list(len(extension_binaries), 2) + extension_binaries

class TLSHandshakeFrame(BaseTLSFrame):
    def __init__(self):
        super().__init__()
        self.tls_record_type = 0x16 # Handshake

    def set_handshake_header(self, data:list):
        result = [self.handshake_type] + int_to_list(len(data), 3) + data
        return self.set_tls_header(result)

class TLSExtension(object):
    extension_types = {
        0: "server_name",
        1: "max_fragment_length",
        5: "status_request",
        10: "supported_groups",
        13: "signature_algorithms",
        14: "use_srtp",
        15: "heartbeat",
        16: "application_layer_protocol_negotiation",
        18: "signed_certificate_timestamp",
        19: "client_certificate_type",
        20: "server_certificate_type",
        21: "padding",
        41: "pre_shared_key",
        42: "early_data",
        43: "supported_versions",
        44: "cookie",
        45: "psk_key_exchange_modes",
        47: "certificate_authorities",
        48: "oid_filters",
        49: "post_handshake_auth",
        50: "signature_algorithms_cert",
        51: "key_share",
    }
    def __init__(self, type_id:int=-1, data:list=[]):
        self.type_id = type_id # unknown
        self.data = data

    @classmethod
    def parse(cls, data: list):
        if len(data) < 4:
            raise ValueError("Too small data")

        type_id = data[0] * 0xff + data[1]

        data_length = data[2] * 0xff + data[3]

        if len(data) != data_length + 4:
            raise ValueError("Broken TLS extension")
        
        result = cls()
        result.type_id = type_id
        result.data = data[4:]

        return result
    
    def get_binary(self):
        return int_to_list(self.type_id, 2) + int_to_list(len(self.data), 2) + self.data
    
    def is_for_client_hello(self):
        return True # FIXME
