import certifi
from datetime import datetime

from cryptography.hazmat.primitives.kdf import hkdf
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec, padding

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from cryptography.x509 import DNSName, load_der_x509_certificate, load_pem_x509_certificate, load_pem_x509_certificates
from cryptography.x509.verification import PolicyBuilder, Store

from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption, load_pem_private_key

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from .utils import int_to_list

X25519 = 0x001D
SECP256R1 = 0x0017

class BaseKey:

    X25519 = 0x001D
    SECP256R1 = 0x0017

    def __init__(self, value:list, key_type):
        self.value = value
        self.key_type = key_type
        self.key_types = {
            0x001D: "X25519",
            0x0017: "secp256r1"
        }
        self.internal_key = None

    @property
    def key_type_str(self):
        if self.key_type in self.key_types:
            return self.key_types[self.key_type]
        else:
            return "Unknown"

    def __str__(self):
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
        elif key_type == cls.SECP256R1:
            result = cls(None, key_type)
            result.internal_key = ec.generate_private_key(
                ec.SECP256R1()
            )
            result.value = "secp256r1-private-key"
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
        if value != None and key_type == self.__class__.X25519:
            self.internal_key = X25519PublicKey.from_public_bytes(bytes(value))
    
    @classmethod
    def from_private(cls, private:PrivateKey):
        if private.key_type == cls.X25519:
            result = cls(None, private.key_type)
            result.internal_key = private.internal_key.public_key()
            result.value = [*result.internal_key.public_bytes_raw()]
            return result
        elif private.key_type == cls.SECP256R1:
            result = cls(None, private.key_type)
            result.internal_key = private.internal_key.public_key()
            nums = result.internal_key.public_numbers()
            result.value = [4] + int_to_list(nums.x, 32) + int_to_list(nums.y, 32)
            return result
        else:
            raise TypeError("unsupported key type")

class SharedKey(BaseKey):
    def __init__(self, value, key_type):
        super().__init__(value, key_type)

class HashAlgorithm(object):
    SHA256 = 1
    SHA384 = 2
    def __init__(self, type_id):
        self.type_id = type_id
        if type_id == self.__class__.SHA256:
            self.algorithm = hashes.SHA256()
        elif type_id == self.__class__.SHA384:
            self.algorithm = hashes.SHA384()
        else:
            self.algorithm = None

    @property
    def length(self):
        if self.algorithm != None:
            return self.algorithm.digest_size
        else:
            return 0

    def hmac(self, key:bytes, value:bytes, encoding="ascii"):
        if type(value) == str:
            value = value.encode(encoding)
        elif isinstance(value, (list, tuple)):
            value = bytes(value)
        elif type(value) != bytes:
            TypeError(type(value).__name__)
        hmacer = hmac.HMAC(key, self.algorithm)
        hmacer.update(value)
        return hmacer.finalize()

    def hash(self, value:bytes, encoding="ascii"):
        if type(value) == str:
            value = value.encode(encoding)
        elif isinstance(value, (list, tuple)):
            value = bytes(value)
        elif type(value) != bytes:
            TypeError(type(value).__name__)
        hasher = hashes.Hash(self.algorithm)
        hasher.update(value)
        return hasher.finalize()

class SignatureAlgorithm(object):
    UNKNOWN = 0
    ECDSA = 1
    RSA = 2

    def __init__(self, type_id):
        self.type_id = type_id
        if type_id == 0x0403:
            self.kind = self.__class__.ECDSA
            self.algorithm = ec.ECDSA(hashes.SHA256())
        elif type_id == 0x0404:
            self.kind = self.__class__.ECDSA
            self.algorithm = ec.ECDSA(hashes.SHA384())
        elif type_id == 0x0804: # "rsa_pss_rsae_sha256",:
            self.kind = self.__class__.RSA
            self.algorithm = hashes.SHA256()
        else:
            self.kind = self.__class__.UNKNOWN
            self.algorithm = None

    def verify(self, public_key, signature, signature_source):
        if self.kind == self.__class__.ECDSA:
            public_key.verify(signature, signature_source, self.algorithm)
        elif self.kind == self.__class__.RSA:
            if self.type_id == 0x0804:
                public_key.verify(
                    signature,
                    signature_source,
                    padding.PSS(
                        mgf=padding.MGF1(self.algorithm),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    self.algorithm
                )
        return True

    def derive(self, private_key, signature_source):
        if self.kind == self.__class__.ECDSA:
            return private_key.sign(signature_source, self.algorithm)
        elif self.kind == self.__class__.RSA:
            if self.type_id == 0x0804:
                return private_key.sign(
                    signature_source,
                    padding.PSS(
                        mgf=padding.MGF1(self.algorithm),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    self.algorithm
                )
        return None

class HKDFLabel(object):
    def __init__(self, label:str, context:str, length:int):
        if type(label) == str:
            self.label = label.encode("ascii")
        else:
            self.label = label
        self.context = context
        self.length = length

    def get_bytes(self):
        return bytes(int_to_list(self.length, 2) + [len(self.label)+6] + [*(b"tls13 "+self.label)] + [len(self.context)] + [*self.context])

def HKDFExpand(secret, hkdf_label, length, hasher):
    if not isinstance(hkdf_label, HKDFLabel):
        raise TypeError("hkdf_label must be HKDFLabel")
    hkdf_exp = hkdf.HKDFExpand(
        algorithm = hasher.algorithm,
        length = length,
        info = hkdf_label.get_bytes()
    )
    key = hkdf_exp.derive(secret)
    return key

def HKDFExpandLabel(secret, label, context, length, hasher):
    return HKDFExpand(secret, HKDFLabel(label, context, length), length, hasher)

def HKDFExtract(salt, ikm, hasher):
    #hkdf_ext = hkdf.HKDF(
    #    algorithm = hasher.algorithm,
    #    length = hasher.length,
    #    salt = salt,
    #    info=None
    #)
    #key = hkdf_ext.derive(ikm)
    if salt == None or len(salt) == 0:
        salt = b"\0" * hasher.length
    # salt -> key, ikm -> value
    key = hasher.hmac(salt, ikm)
    return key

from .frames.base import BaseTLSFrame

def transcript_hash(messages, hasher:HashAlgorithm):
    result = []
    for msg in messages:
        #print(msg.child)
        if isinstance(msg, BaseTLSFrame):
            result.extend(msg.get_binary())
        elif type(msg) == str:
            result.extend(msg.encode("ascii"))
        elif type(msg) == bytes:
            result.extend(msg)
        elif type(msg) == int:
            result.append(msg)
        elif isinstance(msg, (list, tuple)):
            if all([type(i) == int for i in msg]):
                result.extend(msg)
            else:
                raise TypeError("list/tuple elements must be int")
        else:
            raise TypeError("Unusable type " + str(type(msg)))
    #print(result)
    return hasher.hash(bytes(result))

def verify_certificates(leaf, certs: list = []):
    return True # Trust All!

    with open(certifi.where(), "rb") as pems:
        store = Store(load_pem_x509_certificates(pems.read()))
    builder = PolicyBuilder().store(store)
    builder = builder.time(datetime.now())
    verifier = builder.build_server_verifier(DNSName("raspython3.org"))
    # NOTE: peer and untrusted_intermediates are Certificate and
    #       list[Certificate] respectively, and should be loaded from the
    #       application context that needs them verified, such as a
    #       TLS socket.
    chain = verifier.verify(leaf, certs)
    return True

'''
*_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
*_write_iv = HKDF-Expand-Label(Secret, "iv", "", key_length)

HKDF-Expand-Label(Secret, Label, Context, Length) =
    HKDF-Expand(Secret, HkdfLabel, Length)

Where HkdfLabel is specified as:

struct {
    uint16 length = Length;
    opaque label<7..255> = "tls13 " + Label;
    opaque context<0..255> = Context;
} HkdfLabel;

Derive-Secret(Secret, Label, Messages) =
    HKDF-Expand-Label(Secret, Label,
                        Transcript-Hash(Messages), Hash.length)
'''