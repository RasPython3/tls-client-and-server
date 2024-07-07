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
            self.minor_version = value & 0xff - 1
        else:
            raise RuntimeError("Illegal TLS version")

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
        super().__init__()

    def set_tls_header(self, data:list):
        result = [self.tls_record_type, 3, 1] + int_to_list(len(data), 2) + data
        return result

    def get_extensions_binary(self):
        extension_binaries = []

        for extension in self.extensions:
            extension_binaries.extend(extension.get_binary())

        return int_to_list(len(extension_binaries), 2) + extension_binaries

  