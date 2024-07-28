from ..base import TLSHandshakeFrame

from ...common import CertificateEntry

from ... import ext, crypto

from ...utils import int_to_list

class TLSCertificateFrame(TLSHandshakeFrame):
    def __init__(self, context, certs):
        super().__init__()
        self.type_id = 0x0b
        self.context = context
        self.certificates = certs

    @classmethod
    def parse(cls, data: list):
        if len(data) == 0 or len(data) < 4 + data[0]:
            raise RuntimeError("Illegal length")

        context = data[1:data[0]+1]

        index = data[0] + 1

        certs_length_left = data[index] * 0x10000 + data[index+1] * 0x100 + data[index+2]

        if len(data) != 4 + data[0] + certs_length_left:
            raise RuntimeError("Illegal length")

        index += 3

        cert_entries = []
        while certs_length_left > 0:
            if certs_length_left < 3:
                raise RuntimeError("Illegal length")
            cert_data_length = data[index] * 0x10000 + data[index+1] * 0x100 + data[index+2]

            index += 3
            cert_data = crypto.load_der_x509_certificate(bytes(data[index:index+cert_data_length]))
            index += cert_data_length
            certs_length_left -= cert_data_length + 3

            if certs_length_left < 2:
                raise RuntimeError("Illegal length")
            cert_extensions_length = data[index] * 0x100 + data[index+1]

            if certs_length_left - 2 < cert_extensions_length:
                raise RuntimeError("Illegal length")

            k = 0
            cert_extensions = []
            while k < cert_extensions_length:
                extension_length = data[index+k+2] * 0x100 + data[index+k+3]

                if k + extension_length + 4 > cert_extensions_length:
                    raise RuntimeError("Illegal extension length")

                cert_extensions.append(ext.TLSExtension.parse(data[index+k:index+k+extension_length+4], ext.MODE["certificate"]))

                k += extension_length + 4
            
            cert_entries.append(CertificateEntry(
                cert_data,
                cert_extensions
            ))

            certs_length_left -= cert_extensions_length + 2
            index += cert_extensions_length + 2

        if certs_length_left < 0:
            raise RuntimeError("Illegal length")

        return cls(context, cert_entries)

    def get_binary(self):
        cert_binary = []

        for entry in self.certificates:
            cert_binary.extend(entry.get_binary())

        return [len(self.context)] + self.context + int_to_list(len(cert_binary), 3) + cert_binary
