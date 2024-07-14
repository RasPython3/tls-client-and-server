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
        print("".join([f"{i:02X}" for i in handshake_secret]))
        client_secret = HKDFExpandLabel(handshake_secret, "c hs traffic", hello_hash, 48, hasher)
        server_secret = HKDFExpandLabel(handshake_secret, "s hs traffic", hello_hash, 48, hasher)
        print("".join([f"{i:02X}" for i in client_secret]))
        print("".join([f"{i:02X}" for i in server_secret]))
        client_handshake_key = HKDFExpandLabel(client_secret, "key", "", 32, hasher)
        server_handshake_key = HKDFExpandLabel(server_secret, "key", "", 32, hasher)
        client_handshake_iv = HKDFExpandLabel(client_secret, "iv", "", 12, hasher)
        server_handshake_iv = HKDFExpandLabel(server_secret, "iv", "", 12, hasher)
        print("".join([f"{i:02X}" for i in client_handshake_key]))
        print("".join([f"{i:02X}" for i in client_handshake_iv]))
        print("".join([f"{i:02X}" for i in server_handshake_key]))
        print("".join([f"{i:02X}" for i in server_handshake_iv]))

if __name__ == "__main__":
    unittest.main()