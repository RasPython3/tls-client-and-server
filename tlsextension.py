from tlsutils import *

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

        type_id = data[0] * 0x100 + data[1]

        data_length = data[2] * 0x100 + data[3]

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


class TLSSupportedVersionsExtension(TLSExtension):
    def __init__(self, versions:list=[], is_client=True):
        super().__init__()
        self.versions = versions

    @property
    def type_id(self):
        return 43
    
    @type_id.setter
    def type_id(self, value):
        pass

    @property
    def data(self):
        if self.is_client:
            return int_to_list(len(self.versions)*2, 2) + sum([int_to_list(version, 2) for version in self.versions], [])
        else:
            return int_to_list(versions[0], 2)

    @data.setter
    def data(self, value):

class NamedGroup(object):
    named_group_types = {
        # Elliptic Curve Groups (ECDHE)
        0x0017: "secp256r1",
        0x0018: "secp384r1",
        0x0019: "secp521r1",
        0x001D: "x25519",
        0x001E: "x448",

        # Finite Field Groups (DHE)
        0x0100: "ffdhe2048",
        0x0101: "ffdhe3072",
        0x0102: "ffdhe4096",
        0x0103: "ffdhe6144",
        0x0104: "ffdhe8192",

        # Reserved Code Points
        # ffdhe_private_use(0x01FC..0x01FF),
        # ecdhe_private_use(0xFE00..0xFEFF)
    }
    def __init__(self, type_id:int=0):
        self.type_id = type_id # null
    
    @classmethod
    def parse(cls, data: list):
        if len(data) != 2:
            raise ValueError("Illegal size data")

        type_id = data[0] * 0x100 + data[1]

        result = cls()
        result.type_id = type_id

        return result

    def get_binary(self):
        return int_to_list(self.type_id, 2)

class KeyShareEntry(object):
    def __init__(self, group:NamedGroup, key:list):
        super().__init__()
        self.group = group
        self.key = key

    @classmethod
    def parse(cls, data: list):
        if len(data) < 4 or len(data) - 4 != data[2] * 0x100 + data[3]:
            raise RuntimeError("Illegal length")
        result = cls(NamedGroup.parse(data[:2]), data[4:])
        return result

class TLSClientHelloKeyShareExtension(TLSExtension):
    def __init__(self, entries:list):
        super().__init__()
        if any([not isinstance(entry, KeyShareEntry) for entry in entries]):
            raise TypeError("some of given entries are not KeyShareEntry")
        self.enttries = entries

    @property
    def type_id(self):
        return 51
    
    @type_id.setter
    def type_id(self, value):
        pass

    @property
    def data(self):
        pass
    @data.setter
    def data(self, value):
        pass
