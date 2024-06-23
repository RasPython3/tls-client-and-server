from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

X25519 = 0x001D

class BaseKey:

    X25519 = 0x001D

    def __init__(self, value:list, key_type):
        self.value = None
        self.key_type = key_type
        self.key_types = {
            0x001D: "X25519"
        }
        self.internal_key = None

    @property
    def key_type_str(self):
        if self.key_type in self.key_types:
            return self.key_types[self.key_type]
        else:
            return "Unknown"

    def __repr__(self):
        if isinstance(self.value, (list, tuple)):
            return "<{} type={} length={} value=0x{}>".format(
                self.__class__.__name__,
                self.key_type_str,
                str(len(self.value)),
                "".join(["{:0>2X}".format(i) for i in self.value]))
        else:
            return "<{} type={} value={}>".format(
                self.__class__.__name__,
                self.key_type_str,
                str(self.value))

class PrivateKey(BaseKey):
    def __init__(self, value:list, key_type):
        super().__init__(value, key_type)

    @classmethod
    def generate(cls, key_type):
        if key_type == cls.X25519:
            result = cls(None, key_type)
            result.internal_key = X25519PrivateKey.generate()
            result.value = [*result.internal_key.private_bytes_raw()]
            return result
        else:
            raise TypeError("unsupported key type")
    
    def exchange(self, server_public):
        result = SharedKey(None, self.key_type)
        result.value = [*self.internal_key.exchange(server_public.internal_key)]
        return result

class PublicKey(BaseKey):
    def __init__(self, value, key_type):
        super().__init__(value, key_type)
    
    @classmethod
    def from_private(cls, private:PrivateKey):
        if private.key_type == cls.X25519:
            result = cls(None, private.key_type)
            result.internal_key = private.internal_key.public_key()
            result.value = [*result.internal_key.public_bytes_raw()]
            return result
        else:
            raise TypeError("unsupported key type")

class SharedKey(BaseKey):
    def __init__(self, value, key_type):
        super().__init__(value, key_type)