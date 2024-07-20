import unittest

from . import crypto
from .crypto import *

class Testing(unittest.TestCase):
    def test_traffic(self):
        hasher = crypto.HashAlgorithm(crypto.HashAlgorithm.SHA384)
        early_secret = HKDFExtract(None, b"\0"*48, hasher)
        shared_secret = b"\xdf\x4a\x29\x1b\xaa\x1e\xb7\xcf\xa6\x93\x4b\x29\xb4\x74\xba\xad\x26\x97\xe2\x9f\x1f\x92\x0d\xcc\x77\xc8\xa0\xa0\x88\x44\x76\x24"
        empty_hash = hasher.hash("")
        hello_hash = b"\xe0\x5f\x64\xfc\xd0\x82\xbd\xb0\xdc\xe4\x73\xad\xf6\x69\xc2\x76\x9f\x25\x7a\x1c\x75\xa5\x1b\x78\x87\x46\x8b\x5e\x0e\x7a\x7d\xe4\xf4\xd3\x45\x55\x11\x20\x77\xf1\x6e\x07\x90\x19\xd5\xa8\x45\xbd"
        derived_secret = HKDFExpandLabel(early_secret, "derived", empty_hash, 48, hasher)
        handshake_secret = HKDFExtract(derived_secret, shared_secret, hasher)
        self.assertEqual("".join([f"{i:02x}" for i in handshake_secret]), "bdbbe8757494bef20de932598294ea65b5e6bf6dc5c02a960a2de2eaa9b07c929078d2caa0936231c38d1725f179d299")
        print("".join([f"{i:02x}" for i in handshake_secret]))
        client_secret = HKDFExpandLabel(handshake_secret, "c hs traffic", hello_hash, 48, hasher)
        server_secret = HKDFExpandLabel(handshake_secret, "s hs traffic", hello_hash, 48, hasher)
        self.assertEqual("".join([f"{i:02x}" for i in client_secret]), "db89d2d6df0e84fed74a2288f8fd4d0959f790ff23946cdf4c26d85e51bebd42ae184501972f8d30c4a3e4a3693d0ef0")
        print("".join([f"{i:02X}" for i in client_secret]))
        self.assertEqual("".join([f"{i:02x}" for i in server_secret]), "23323da031634b241dd37d61032b62a4f450584d1f7f47983ba2f7cc0cdcc39a68f481f2b019f9403a3051908a5d1622")
        print("".join([f"{i:02X}" for i in server_secret]))
        client_handshake_key = HKDFExpandLabel(client_secret, "key", "", 32, hasher)
        server_handshake_key = HKDFExpandLabel(server_secret, "key", "", 32, hasher)
        client_handshake_iv = HKDFExpandLabel(client_secret, "iv", "", 12, hasher)
        server_handshake_iv = HKDFExpandLabel(server_secret, "iv", "", 12, hasher)
        self.assertEqual("".join([f"{i:02x}" for i in client_handshake_key]), "1135b4826a9a70257e5a391ad93093dfd7c4214812f493b3e3daae1eb2b1ac69")
        self.assertEqual("".join([f"{i:02x}" for i in server_handshake_key]), "9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f")
        self.assertEqual("".join([f"{i:02x}" for i in client_handshake_iv]), "4256d2e0e88babdd05eb2f27")
        self.assertEqual("".join([f"{i:02x}" for i in server_handshake_iv]), "9563bc8b590f671f488d2da3")
        print("".join([f"{i:02X}" for i in client_handshake_key]))
        print("".join([f"{i:02X}" for i in client_handshake_iv]))
        print("".join([f"{i:02X}" for i in server_handshake_key]))
        print("".join([f"{i:02X}" for i in server_handshake_iv]))

    def test_transcript_hash(self):
        #


if __name__ == "__main__":
    unittest.main()