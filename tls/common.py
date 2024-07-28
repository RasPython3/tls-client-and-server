import secrets
from . import crypto

from .utils import *

class TLSVersion:
    def __init__(self, version:str):
        if isinstance(version, int):
            self.value = version
        elif isinstance(version, str):
            if len(version.split(".")) != 2:
                raise RuntimeError("Illegal TLS version")
            for ver_str in version.split("."):
                if not ver_str.isdecimal():
                    raise RuntimeError("Illegal TLS version")
            self.major_version, self.minor_version = [int(ver_str) for ver_str in version.split(".")]
        else:
            raise TypeError("version")

    def __eq__(self, other):
        if isinstance(other, TLSVersion):
            return self.value == other.value
        elif isinstance(other, int):
            return self.value == other
        return False

    def __ne__(self, other):
        if isinstance(other, TLSVersion):
            return self.value != other.value
        elif isinstance(other, int):
            return self.value != other
        return True

    def __lt__(self, other):
        if isinstance(other, TLSVersion):
            return self.value < other.value
        elif isinstance(other, int):
            return self.value < other
        raise TypeError(f"'<' not supported between instances of 'TLSVersion' and '{type(other)}'")

    def __le__(self, other):
        if isinstance(other, TLSVersion):
            return self.value <= other.value
        elif isinstance(other, int):
            return self.value <= other
        raise TypeError(f"'<=' not supported between instances of 'TLSVersion' and '{type(other)}'")

    def __gt__(self, other):
        if isinstance(other, TLSVersion):
            return self.value > other.value
        elif isinstance(other, int):
            return self.value > other
        raise TypeError(f"'>' not supported between instances of 'TLSVersion' and '{type(other)}'")

    def __ge__(self, other):
        if isinstance(other, TLSVersion):
            return self.value >= other.value
        elif isinstance(other, int):
            return self.value >= other
        raise TypeError(f"'>=' not supported between instances of 'TLSVersion' and '{type(other)}'")

    @property
    def value(self):
        if self.major_version == 1:
            # TLS1.0, TLS1.1, TLS1.2, TLS1.3, ...
            return 0x0300 + self.minor_version + 1
        elif self.major_version == 0 and self.minor_version <= 3:
            # SSL1.0, SSL2.0, SSL3.0
            # Should not use
            return self.minor_version * 0x100
        else:
            raise RuntimeError("Illegal or unsupported TLS/SSL version")

    @value.setter
    def value(self, value:int):
        if not isinstance(value, int):
            raise TypeError("Illegal value")
        if value == 0x0100:
            # SSL1.0
            self.major_version = 0
            self.minor_version = 1
        elif value == 0x0200:
            # SSL2.0
            self.major_version = 0
            self.minor_version = 2
        elif value == 0x0300:
            # SSL3.0
            self.major_version = 0
            self.minor_version = 3
        elif value & 0xff00 == 0x0300:
            # TLS
            self.major_version = 1
            self.minor_version = (value & 0xff) - 1
        else:
            raise RuntimeError("Illegal TLS version")

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

class CipherSuite(object):
    cipher_suite_types = {
        0x1301: "TLS_AES_128_GCM_SHA256",
        0x1302: "TLS_AES_256_GCM_SHA384",
        0x1303: "TLS_CHACHA20_POLY1305_SHA256",
        0x1304: "TLS_AES_128_CCM_SHA256",
        0x1305: "TLS_AES_128_CCM_8_SHA256",
    }
    def __init__(self, type_id:int=0):
        self.type_id = type_id # null
        if type_id in (0x1301, 0x1303, 0x1304, 0x1305):
            self.hash_algorithm = crypto.HashAlgorithm(crypto.HashAlgorithm.SHA256)
        elif type_id in (0x1302,):
            self.hash_algorithm = crypto.HashAlgorithm(crypto.HashAlgorithm.SHA384)
        else:
            self.hash_algorithm = None
    
    @classmethod
    def parse(cls, data: list):
        if len(data) != 2:
            raise ValueError("Wrong size data")

        type_id = data[0] * 0x100 + data[1]

        result = cls(type_id)

        return result
    
    def get_binary(self):
        return int_to_list(self.type_id, 2)

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
        self.signature_algorithm = crypto.SignatureAlgorithm(sig_id)
    
    @classmethod
    def parse(cls, data: list):
        if len(data) != 2:
            raise ValueError("Illegal size data")

        sig_id = data[0] * 0x100 + data[1]

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
        if self.group.group_id in (0x0017, 0x001d): # secp256r1, X25519
            key_exchange_field = self.key
        else:
            raise RuntimeError("unsupported named group. Only secp256r1 and X25519 are supported.")
        if isinstance(key_exchange_field, crypto.BaseKey):
            key_exchange_field = key_exchange_field.value
        return self.group.get_binary() + int_to_list(len(key_exchange_field), 2) + key_exchange_field

    @classmethod
    def parse(cls, data: list):
        if len(data) < 4 or len(data) - 4 != data[2] * 0x100 + data[3]:
            raise RuntimeError("Illegal length")
        result = cls(NamedGroup.parse(data[:2]), data[4:])
        return result

class CertificateEntry(object):
    def __init__(self, certificate, extensions):
        self.certificate = certificate
        self.extensions = extensions

    def get_binary(self):
        cert_data_binary = [*self.certificate.public_bytes(crypto.Encoding.DER)]
        extension_binaries = []
        for extension in self.extensions:
            extension_binaries.extend(extension.get_binary())

        return int_to_list(len(cert_data_binary), 3) + cert_data_binary + int_to_list(len(extension_binaries), 2) + extension_binaries


class ObjDict(dict):
    # object-like dict
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for key in self.keys():
            self._check(key)
        for key in self.__class__.__dict__:
            if not key.startswith("__") and not key.endswith("__") and key != "_check":
                self[key] = getattr(self.__class__, key)
    #
    def _check(self, name):
        if type(name) != str:
            raise RuntimeError("Key must be str")
        if len(name) == 0:
            raise RuntimeError("Zero length key")
        if name[0].lower() not in "abcdefghijklmnopqrstuvwxyz_":
            raise RuntimeError("Keys of ObjDict must start with a-z, A-Z or _")
        if name in self.__dir__():
            if name not in self.__class__.__dict__ or name.startswith("__") or name.endswith("__") or name == "_check":
                raise RuntimeError("Reserved key: "+name)
    #
    def __getattr__(self, name):
        return self[name]
    #
    def __setattr__(self, name, value):
        self._check(name)
        self[name] = value
    #
    def __setitem__(self, name, value):
        self._check(name)
        return super().__setitem__(name, value)