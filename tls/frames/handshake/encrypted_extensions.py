from ..base import TLSHandshakeFrame

from ... import ext

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

