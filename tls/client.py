from .common import *
from .base import *

from . import ext, crypto

from .server import *

import secrets
import socket

def print_tree(data, direction=0): # 0: in, 1: out
    target = data
    indent = 0
    if direction == 0:
        print("--> ", end="")
    else:
        print("<-- ", end="")
    while isinstance(target, NetworkFrame):
        print("  " * indent + target.__class__.__name__)
        if hasattr(target, "extensions"):
            print("  " * indent + "- ext:")
            for extension in target.extensions:
                print("  " * (indent+1) + extension.__class__.__name__)
        if isinstance(target, TLSParentFrame):
            target = target.child
            if indent == 0:
                indent = 3
            else:
                indent += 1
        else:
            break
    print()


class Client:
    def __init__(self, *, version=TLSVersion("1.3")):
        if version != TLSVersion("1.3"):
            raise RuntimeError("Only TLS 1.3 is supported")
        self.version = version
        self.sock = None
        self._isconnected = False
        self.random = {"client": None, "server": None}
        self.private_key = {"client": None, "server": None}
        self.public_key = {"client": None, "server": None}
        self.shared_key = None
        self.handshake_key = None
        self.handshake_iv = None
        self.application_key = None
        self.application_iv = None
        self.recv_cache = []
        self.all_cache = []
        self.received_frames = []
        self.received_alert = None
        self.cipher_suite = None

        self.phase = 0
        # -1 ... FATAL (closed by server)
        # 0 ... SOCK NOT CONNECTED / CLOSED
        # 1 ... START
        # 2 ... WAIT_SERVER_HELLO
        # 3 ... WAIT_ENCRYPTED_EXTENSIONS
        # 4 ... WAIT_CERT_CERTREQ
        # 5 ... WAIT_CERT
        # 6 ... WAIT_CERT_VERIFY
        # 7 ... WAIT_FINISHED
        # 8 ... CONNECTED

    @property
    def isconnected(self):
        return self._isconnected

    def check_connected(self):
        if not self.isconnected:
            raise RuntimeError("Client is not connected to the server yet.")

    def send(self, data:NetworkFrame):
        self.check_connected()
        print_tree(data, 1)
        self.all_cache.append(data.child)
        return self.sock.send(bytes(data.get_binary()))

    def recv(self):
        received = False
        while not received:
            self.check_connected()

            tls_type = -1
            tls_length = -1
            data = [*self.recv_cache]
            self.recv_cache = []

            buffer_size = 5 # TLS header
            while tls_length < 0 or len(data) < 5 + tls_length:
                data.extend(self.sock.recv(buffer_size))

                if tls_length < 0 and len(data) >= 5:
                    tls_type = data[0]
                    tls_length = data[3] * 0xff + data[4]
                    buffer_size = tls_length - len(data) + 5
            
            if len(data) > 5 + tls_length:
                self.recv_cache.extend(data[tls_length+5:])

            result = TLSRecordFrame.parse(data[:tls_length+5])

            if result.child_id == 22: #Handshake Frame
                if result.child.child_id == 0x01: # Client Hello
                    result.child.child = TLSClientHelloFrame.parse(result.child.child.data)
                elif result.child.child_id == 0x02: # Server Hello
                    result.child.child = TLSServerHelloFrame.parse(result.child.child.data)
                elif result.child.child_id == 0x06: # Hello Retry Request
                    result.child.child_id = TLSHelloRetryRequest.parse(result.child.child.data)

            self.received_frames.append(result)
            self.all_cache.append(result.child)

            print_tree(result, 0)

            if result.child_id == 21:
                # Alert
                self.received_alert = result.child
                if result.child.level == 2:
                    # Fatal
                    self.phase = -1
            else:
                received = True

            self.check_phase()

        return result

    def check_phase(self):
        self.check_fatal()
        if self.received_alert != None:
            print("Ignored alert: " + self.received_alert.get_description_text())
            self.received_alert = None

    def check_fatal(self):
        if self.phase == -1 and self.received_alert != None:
            self.close()
            raise RuntimeError("The server returned fatal alert: " + self.received_alert.get_description_text())

    def transcript_hash(self, msgs):
        data = []
        if len(msgs) >= 2 and \
            isinstance(msgs[0], TLSRecordFrame) and \
            isinstance(msgs[0].child, TLSHandshakeFrame) and \
            isinstance(msgs[0].child.child, TLSClientHelloFrame) and \
            isinstance(msgs[1], TLSRecordFrame) and \
            isinstance(msgs[1].child, TLSHandshakeFrame) and \
            isinstance(msgs[1].child.child, TLSHelloRetryRequestFrame):
            data.append(
                TLSRecordFrame(
                    TLSHandshakeFrame(
                        TLSMessageHashFrame(
                            msgs[0], self.cipher_suite.hash_algorithm
                        )
                    )
                )
            )
            data.extend(msgs[1:])
        else:
            data.extend(msgs)
        return transcriptHash(data)

    def connect(self, address:str, port:int):
        if self.phase != 0:
            return
        if self.isconnected:
            raise RuntimeError("Already connected")
        self.sock = socket.create_connection((address, port))
        self._isconnected = True

    def close(self, raise_exception=False):
        if self.phase not in (-1, 0, 1):
            alert = TLSAlertFrame(2, 90)
            self.send(
                TLSRecordFrame(
                    alert
                )
            )
        self.phase = 0
        try:
            self.sock.close()
            self.sock.shutdown(socket.SHUT_RD)
            return True
        except Exception as e:
            if raise_exception:
                raise e
            return False

    def handshake(self):
        self.check_connected()

        client_random = self.random["client"] = gen_random(32)

        self.private_key["client"] = crypto.PrivateKey.generate(crypto.X25519)
        self.public_key["client"] = crypto.PublicKey.from_private(self.private_key["client"])

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
                ext.KeyShareEntry(ext.NamedGroup(0x001d), self.public_key["client"])
            ])
        ) # key share

        server_hello = None

        while self.phase in (0, 2):
            self.phase = 1

            self.send(
                TLSRecordFrame(
                    TLSHandshakeFrame(
                        client_hello
                    )
                )
            )

            self.phase = 2

            server_hello = self.recv()

            if server_hello.child_id != 22 or server_hello.child.child_id not in (0x02, 0x06):
                raise RuntimeError("Illegal message!")

            if server_hello.child.child_id == 0x06:
                # HelloRetryRequest
                continue
            else:
                self.phase = 3

        server_hello = server_hello.child.child

        if all([extension.type_id != 43 for extension in server_hello.extensions]):
            raise RuntimeError("Could not negotiate with TLS 1.3")

        if server_hello.cipher_suite.type_id not in [cipher_suite.type_id for cipher_suite in client_hello.cipher_suites]:
            raise RuntimeError("Illegal CipherSuite!")

        for extension in server_hello.extensions:
            if extension.type_id == 51:
                if extension.entry.group.group_id == 0x001d: # X25519, must always True
                    self.public_key["server"] = crypto.PublicKey(extension.entry.key.value, crypto.X25519)
                    self.shared_key = self.private_key["client"].exchange(self.public_key["server"])

        if self.shared_key == None:
            raise RuntimeError("Could not get shared key")

        encrypted_extensions = None
        recv_change_cipher_spec = False # for compatibility
        while self.phase == 3:
            encrypted_extensions = self.recv()
            if encrypted_extensions.child_id == 20 and recv_change_cipher_spec == False:
                recv_change_cipher_spec = True
                continue
            if encrypted_extensions.child_id == 23:
                self.phase = 4
            else:
                raise RuntimeError("Illegal message!")

        self.close()



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
