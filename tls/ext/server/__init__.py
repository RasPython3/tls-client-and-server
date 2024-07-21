from .server_hello import TLSSupportedVersionsExtension, TLSKeyShareExtension
from .encrypted_extensions import EncryptedExtensionsExtensions

__all__ = (
    "ServerHelloExtensions",
    "EncryptedExtensionsExtensions"
)

class ServerHelloExtensions:
    SupportedVersions = TLSSupportedVersionsExtension
    KeyShare = TLSKeyShareExtension

class EncryptedExtensionsExtensions:
    pass
