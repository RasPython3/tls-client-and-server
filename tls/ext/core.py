from ..utils import *
from .. import crypto

MODE = {
    "client_hello": 0,
    "server_hello": 1,
    "hello_retry_request": 2,
}

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
        self._type_id = type_id # unknown
        self.data = data

    @property
    def type_id(self):
        return self._type_id
    
    @type_id.setter
    def type_id(self, value):
        if self.__class__ == TLSExtension:
            self._type_id = value

    @classmethod
    def parse(orgcls, data: list, mode=None):
        if len(data) < 4:
            raise ValueError("Too small data")

        type_id = data[0] * 0x100 + data[1]

        data_length = data[2] * 0x100 + data[3]

        if len(data) != data_length + 4:
            raise ValueError("Broken TLS extension")

        if mode == "client_hello" or MODE["client_hello"]:
            mod = client.client_hello
        elif mode == "server_hello" or MODE["server_hello"]:
            mod = server.server_hello
        else:
            mod = None
        
        if mod != None:
            if type_id in orgcls.extension_types:
                cls_name = "TLS" + "".join([word.capitalize() for word in orgcls.extension_types[type_id].split("_")]) + "Extension"
                if hasattr(mod, cls_name):
                    cls = getattr(mod, cls_name)
                    return cls.parse(data[4:])

        result = orgcls()
        result.type_id = type_id
        result.data = data[4:]

        return result
    
    def get_binary(self):
        return int_to_list(self.type_id, 2) + int_to_list(len(self.data), 2) + self.data
    
    def is_for_client_hello(self):
        return True # FIXME

class NamedGroup(object):
    named_group_list = {
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
    def __init__(self, group_id:int=0):
        self.group_id = group_id # null
    
    @classmethod
    def parse(cls, data: list):
        if len(data) != 2:
            raise ValueError("Illegal size data")

        group_id = data[0] * 0x100 + data[1]

        result = cls(group_id)

        return result

    @property
    def value(self):
        # un-neccessary?
        return self.group_id

    def get_binary(self):
        return int_to_list(self.group_id, 2)

class SignatureScheme(object):
    signature_algorithm_list = {
        # RSASSA-PKCS1-v1_5 algorithms
        0x0401: "rsa_pkcs1_sha256",
        0x0501: "rsa_pkcs1_sha384",
        0x0601: "rsa_pkcs1_sha512",

        # ECDSA algorithms
        0x0403: "ecdsa_secp256r1_sha256",
        0x0503: "ecdsa_secp384r1_sha384",
        0x0603: "ecdsa_secp521r1_sha512",

        # RSASSA-PSS algorithms with public key OID rsaEncryption
        0x0804: "rsa_pss_rsae_sha256",
        0x0805: "rsa_pss_rsae_sha384",
        0x0806: "rsa_pss_rsae_sha512",

        # EdDSA algorithms
        0x0807: "ed25519",
        0x0808: "ed448",

        # RSASSA-PSS algorithms with public key OID RSASSA-PSS
        0x0809: "rsa_pss_pss_sha256",
        0x080a: "rsa_pss_pss_sha384",
        0x080b: "rsa_pss_pss_sha512",

        # Legacy algorithms
        0x0201: "rsa_pkcs1_sha1",
        0x0203: "ecdsa_sha1",
    }
    def __init__(self, sig_id:int):
        self.sig_id = sig_id
    
    @classmethod
    def parse(cls, data: list):
        if len(data) != 2:
            raise ValueError("Illegal size data")

        group_id = data[0] * 0x100 + data[1]

        result = cls(sig_id)

        return result

    @property
    def value(self):
        # un-neccessary?
        return self.sig_id

    def get_binary(self):
        return int_to_list(self.sig_id, 2)

class SignatureSchemeList(list):
    def __init__(self, *schemes):
        super().__init__(schemes)

    @classmethod
    def parse(cls, data: list):
        if len(data) < 2 or len(data) - 2 != data[1] * 0x100 + data[0]:
            raise RuntimeError("Illegal length")
        schemes = []
        for i in range(2, len(data), 2):
            schemes.append(SignatureScheme.parse(data[i:i+2]))
        result = cls(*schemes)
        return result

    def get_binary(self):
        result = int_to_list(len(self)*2, 2)
        for scheme in self:
            result.extend(scheme.get_binary())
        return result


class KeyShareEntry(object):
    def __init__(self, group:NamedGroup, key:crypto.BaseKey):
        super().__init__()
        self.group = group
        if isinstance(key, (list, tuple)):
            self.key = crypto.BaseKey(key, -1)
        else:
            self.key = key

    def get_binary(self):
        if self.group.group_id == 0x001d: # X25519
            key_exchange_field = self.key
        else:
            raise RuntimeError("unsupported named group. Only X25519 is supported.")
        if isinstance(key_exchange_field, crypto.BaseKey):
            key_exchange_field = key_exchange_field.value
        return self.group.get_binary() + int_to_list(len(key_exchange_field), 2) + key_exchange_field

    @classmethod
    def parse(cls, data: list):
        if len(data) < 4 or len(data) - 4 != data[2] * 0x100 + data[3]:
            raise RuntimeError("Illegal length")
        result = cls(NamedGroup.parse(data[:2]), data[4:])
        return result

# To prevent circular import, import them here
from . import client, server
