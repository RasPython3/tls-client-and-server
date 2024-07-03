from .common import *
from .base import *

from . import ext

from .server import *

import secrets
import socket

def print_tree(data):
    target = data
    indent = 0
    while isinstance(target, NetworkFrame):
        print("  " * indent + target.__class__.__name__)
        if hasattr(target, "extensions"):
            print("  " * indent + "- ext: " + ", ".join([ext.__class__.__name__ for ext in target.extensions]))
        if isinstance(target, TLSParentFrame):
            target = target.child
            indent += 1
        else:
            break

class TLSClientHelloFrame(TLSHandshakeFrame):
    def __init__(self):
        super().__init__()
        self.type_id = 0x01 # Client Hello

        self.tls_version =  TLSVersion("1.2") # TLS 1.2
        self.random = None
        self.legacy_session_id = None
        self.cipher_suites = []
        self.legacy_compression_methods = []
        self.extensions = []
    
    @classmethod
    def parse(cls, data:list):
        if len(data) < 53:
            raise ValueError("Too small data")
        
        result = cls()
        
        result.tls_version = data[0] * 0x100 + data[1]

        result.random = data[2:34]

        index = 34

        result.legacy_session_id = data[35:35+data[index]]

        index += data[index] + 1

        for k in range(0, data[index] * 0x100 + data[index+1], 2):
            result.cipher_suites.append(TLSCipherSuite.parse(data[index+k+2:index+k+4]))

        index += 2 + len(result.cipher_suites) * 2

        for k in range(0, data[index]):
            result.legacy_compression_methods.append(data[index+k+1])

        index += data[index] + 1

        extensions_length = data[index] * 0x100 + data[index+1]

        k = 2
        while k < extensions_length + 2:
            extension_length = data[index+k+2] * 0x100 + data[index+k+3]

            if k + extension_length + 4 > extensions_length + 2:
                raise RuntimeError("Illegal extension length")

            result.extensions.append(ext.TLSExtension.parse(data[index+k:index+k+extension_length+4], ext.MODE["client_hello"]))

            k += extension_length + 4

        return result

    def get_binary(self):
        if not isinstance(self.random, (list, tuple)) or len(self.random) != 32:
            raise RuntimeError("ClientHello random is not set or a wrong value")
        
        result = []

        # Protocol Version
        result.extend([3, 3]) # 0x0303

        # random
        result.extend(self.random)

        # legacy session id ( ignore )
        result.extend([0])

        # cipher suites
        result.extend(int_to_list(len(self.cipher_suites) * 2, 2))
        for cipher_suite in self.cipher_suites:
            result.extend(int_to_list(cipher_suite.type_id, 2))

        # legacy compression methods
        result.extend([1, 0])

        result.extend(self.get_extensions_binary())

        return result


class Client:
    def __init__(self, *, version=TLSVersion("1.3")):
        if version != TLSVersion("1.3"):
            raise RuntimeError("Only TLS 1.3 is supported")
        self.version = version
        self.sock = None
        self._isconnected = False
        self.random = {"client": None, "server": None}
        self.cache = []
    
    @property
    def isconnected(self):
        return self._isconnected
    
    def check_connected(self):
        if not self.isconnected:
            raise RuntimeError("Client is not connected to the server yet.")
    
    def send(self, data:NetworkFrame):
        self.check_connected()
        print_tree(data)
        return self.sock.send(bytes(data.get_binary()))

    def recv(self):
        self.check_connected()

        tls_type = -1
        tls_length = -1
        data = [*self.cache]
        self.cache = []
        
        buffer_size = 5 # TLS header
        while tls_length < 0 or len(data) < 5 + tls_length:
            data.extend(self.sock.recv(buffer_size))

            if tls_length < 0 and len(data) >= 5:
                tls_type = data[0]
                tls_length = data[3] * 0xff + data[4]
                buffer_size = tls_length - len(data) + 5
        
        if len(data) > 5 + tls_length:
            self.cache.extend(data[tls_length+5:])

        result = TLSRecordFrame.parse(data[:tls_length+5])

        if result.child_id == 22: #Handshake Frame
            if result.child.child_id == 0x01: # Client Hello
                result.child.child = TLSClientHelloFrame.parse(result.child.child.data)
            elif result.child.child_id == 0x02: # Server Hello
                result.child.child = TLSServerHelloFrame.parse(result.child.child.data)

        print_tree(result)
        print()

        return result
    
    def connect(self, address:str, port:int):
        if self.isconnected:
            raise RuntimeError("Already connected")
        self.sock = socket.create_connection((address, port))
        self._isconnected = True
    
    def handshake(self):
        self.check_connected()

        client_random = self.random["client"] = gen_random(32)

        self.private_key = crypto.PrivateKey.generate(crypto.X25519)
        self.public_key = crypto.PublicKey.from_private(self.private_key)

        self.shared_key = None

        client_hello = TLSClientHelloFrame()
        client_hello.random = client_random
        client_hello.cipher_suites.append(TLSCipherSuite(0x1301))
        client_hello.extensions.append(
            ext.client.client_hello.TLSSupportedVersionsExtension([TLSVersion("1.3")])
        ) # supported versions
        client_hello.extensions.append(
            ext.client.client_hello.TLSSignatureAlgorithmsExtension([ext.SignatureScheme(0x0403)])
        ) # signature algorithms
        client_hello.extensions.append(
            ext.client.client_hello.TLSSupportedGroupsExtension([ext.NamedGroup(0x001d)])
        ) # supported groups ecdhe x25195
        client_hello.extensions.append(
            ext.client.client_hello.TLSKeyShareExtension([
                ext.KeyShareEntry(ext.NamedGroup(0x001d), self.public_key)
            ])
        ) # key share

        self.send(
            TLSRecordFrame(
                TLSHandshakeFrame(
                    client_hello
                )
            ))

        server_hello = self.recv()

        if server_hello.child_id != 22 or server_hello.child.child_id != 0x02:
            raise RuntimeError("Illegal message!")

        server_hello = server_hello.child.child

        if all([extension.type_id != 43 for extension in server_hello.extensions]):
            raise RuntimeError("Could not negotiate with TLS 1.3")

        encrypted_extensions = None
        recv_change_cipher_spec = False # for compatibility
        while True:
            encrypted_extensions = self.recv()
            if encrypted_extensions.child_id == 20 and recv_change_cipher_spec == False:
                recv_change_cipher_spec = True
                continue
            if encrypted_extensions.child_id == 23:
                break
            else:
                raise RuntimeError("Illegal message!")

        try:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()
        except:
            pass
