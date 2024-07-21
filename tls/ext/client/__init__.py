from .client_hello import TLSSupportedVersionsExtension, TLSSupportedGroupsExtension, TLSSignatureAlgorithmsExtension, TLSKeyShareExtension

__all__ = (
    "ClientHelloExtensions",
)

class ClientHelloExtensions:
    SupportedVersions = TLSSupportedVersionsExtension
    SupportedGroups = TLSSupportedGroupsExtension
    SignatureAlgorithms = TLSSignatureAlgorithmsExtension
    KeyShare = TLSKeyShareExtension