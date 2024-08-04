from ..utils import *
from .. import crypto

__all__ = (
    "MODE",
    "TLSExtension"
)

MODE = {
    "client_hello": 0,
    "server_hello": 1,
    "hello_retry_request": 2,
    "encrypted_extensions": 3
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

        if mode == "client_hello" or mode == MODE["client_hello"]:
            exts = ClientHelloExtensions
        elif mode == "server_hello" or mode == MODE["server_hello"]:
            exts = ServerHelloExtensions
        else:
            exts = None

        if exts != None:
            if type_id in orgcls.extension_types:
                cls_name = "".join([word.capitalize() for word in orgcls.extension_types[type_id].split("_")])
                if hasattr(exts, cls_name):
                    cls = getattr(exts, cls_name)
                    return cls.parse(data[4:])

        result = orgcls()
        result.type_id = type_id
        result.data = data[4:]

        return result

    def get_binary(self):
        return int_to_list(self.type_id, 2) + int_to_list(len(self.data), 2) + self.data
    
    def is_for_client_hello(self):
        return True # FIXME

# To prevent circular import, import them here
from .client import ClientHelloExtensions
from .server import ServerHelloExtensions, EncryptedExtensionsExtensions
