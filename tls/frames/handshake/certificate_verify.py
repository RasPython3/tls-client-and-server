from ..base import TLSHandshakeFrame

from ...common import SignatureScheme

from ...utils import int_to_list

class TLSCertificateVerifyFrame(TLSHandshakeFrame):
    def __init__(self, signature_algorithm, signature:list):
        super().__init__()
        self.type_id = 0x0f
        self.signature_scheme = signature_algorithm
        self.signature = signature

    @classmethod
    def parse(cls, data: list):
        if len(data) < 4:
            raise RuntimeError("Illegal length")

        sig_scheme = SignatureScheme.parse(data[:2])

        sig_length = data[2] * 0x100 + data[3]

        if len(data) != sig_length + 4:
            raise RuntimeError("Illegal length")

        signature = data[4:]

        return cls(sig_scheme, signature)

    def get_binary(self):
        return self.signature_scheme.get_binary() + int_to_list(len(self.signature), 2) + self.signature