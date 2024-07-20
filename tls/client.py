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
        self.secret = {"client": None, "server": None}
        self.private_key = {"client": None, "server": None}
        self.public_key = {"client": None, "server": None}
        self.shared_key = None
        self.handshake_secret = None
        self.handshake_key = {"client": None, "server": None}
        self.handshake_iv = {"client": None, "server": None}
        self.application_key = {"client": None, "server": None}
        self.application_iv = {"client": None, "server": None}
        self.recv_cache = []
        self.all_cache = []
        self.received_frames = []
        self.received_alert = None
        self.cipher_suite = None

        self.phase = 0
        self.record_num = {"client": 0, "server": 0}
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

    def raw_send(self, data:NetworkFrame):
        self.check_connected()
        print_tree(data, 1)
        if isinstance(data, TLSRecordFrame) and \
            data.child_id == 22: # Handshake
            self.all_cache.append(data)
        if self.phase >= 3: # encrypted
            if isinstance(data, TLSRecordFrame):
                if self.phase < 8: # Handshake
                    data = self.encrypt_message(
                        data,
                        self.handshake_key["client"],
                        self.handshake_iv["client"]
                    )
                else: # Application
                    data = self.encrypt_message(
                        data,
                        self.application_key["client"],
                        self.application_iv["client"]
                    )
            self.record_num["client"] += 1
        return self.sock.send(bytes(data.get_binary()))

    def raw_recv(self, recv_alert=False):
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
                    tls_length = data[3] * 0x100 + data[4]
                    buffer_size = tls_length - len(data) + 5
            
            if len(data) > 5 + tls_length:
                self.recv_cache.extend(data[tls_length+5:])

            result = TLSRecordFrame.parse(data[:tls_length+5])

            plaintext = None
            if result.child_id == 23: # Application Data, encrypted
                if self.phase < 8:
                    self.decrypt_message(result, self.handshake_key["server"], self.handshake_iv["server"])
                else:
                    self.decrypt_message(result, self.application_key["server"], self.application_iv["server"])
                self.record_num["server"] += 1
                plaintext = TLSInnerPlaintext.parse(result.child.raw_data)
                #print([plaintext.content_type] + \
                #    int_to_list(result.tls_version, 2) + \
                #    int_to_list(len(plaintext.content), 2))
                #print(plaintext.content)
                result = TLSRecordFrame.parse(
                    [plaintext.content_type] + \
                    int_to_list(result.tls_version, 2) + \
                    int_to_list(len(plaintext.content), 2) + \
                    plaintext.content
                )

            if result.child_id == 22: #Handshake Frame
                if result.child.child_id == 0x01: # Client Hello
                    result.child.child = TLSClientHelloFrame.parse(result.child.child.data)
                elif result.child.child_id == 0x02: # Server Hello
                    result.child.child = TLSServerHelloFrame.parse(result.child.child.data)
                elif result.child.child_id == 0x06: # Hello Retry Request
                    result.child.child = TLSHelloRetryRequest.parse(result.child.child.data)
                elif result.child.child_id == 0x08: # Encrypted Extensions
                    result.child.child = TLSEncryptedExtensionsFrame.parse(result.child.child.data)
                elif result.child.child_id == 0x0b: # Certificate
                    result.child.child = TLSCertificateFrame.parse(result.child.child.data)
                elif result.child.child_id == 0x0f: # Certificate Verify
                    result.child.child = TLSCertificateVerifyFrame.parse(result.child.child.data)
                elif result.child.child_id == 0x14: # Finished
                    result.child.child = TLSFinishedFrame.parse(result.child.child.data)
                self.all_cache.append(result)
            elif result.child_id == 23: # Application Data
                result.child = TLSApplicationDataFrame.parse(result.child.encrypted_data)

            self.received_frames.append(result)

            if (plaintext == None and data[:tls_length+5] != result.get_binary()) or \
                (plaintext != None and plaintext.content != result.child.get_binary()):
                print("decode-then-encode failed")
                al = data[:tls_length+5]
                bl = result.get_binary()
                cl = []
                for i in range(len(al)):
                    cl.append(al[i] - bl[i])
                print(cl)

            print_tree(result, 0)

            if result.child_id == 21:
                # Alert
                self.received_alert = result.child
                if result.child.level == 2:
                    # Fatal
                    self.phase = -1
                received = recv_alert
            else:
                received = True

            self.check_phase()

        return result

    def send(self, data:list):
        print(data)
        if self.phase != 8:
            raise RuntimeError("not ready or disconnected")

        if type(data) == str:
            data = [*data.encode("utf-8")]

        packet = TLSRecordFrame(
            TLSApplicationDataFrame(data)
        )

        self.raw_send(packet)

    def recv(self):
        if self.phase != 8:
            raise RuntimeError("not ready or disconnected")

        packet = None

        while True:
            packet = self.raw_recv()
            if packet.child_id == 23:
                #print(packet.child)
                data = packet.child.data
                print(data)
                return data

    def check_phase(self):
        self.check_fatal()
        if self.received_alert != None:
            print("alert ( warning ) : " + self.received_alert.get_description_text())
            self.received_alert = None

    def check_fatal(self):
        if self.phase == -1 and self.received_alert != None:
            self.close()
            raise RuntimeError("The server returned fatal alert: " + self.received_alert.get_description_text())

    def transcript_hash_msgs(self, msgs, hasher) -> bytes:
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
        return transcript_hash([i.child for i in data], hasher)

    def generate_handshake_secrets(self):
        hasher = self.cipher_suite.hash_algorithm
        early_secret = crypto.HKDFExtract(None, b"\0"*hasher.length, hasher)
        shared_secret = bytes(self.shared_key.value)
        empty_hash = hasher.hash("")
        hello_hash = self.transcript_hash_msgs(self.all_cache, hasher)
        derived_secret = crypto.HKDFExpandLabel(early_secret, "derived", empty_hash, hasher.length, hasher)
        self.handshake_secret = handshake_secret = crypto.HKDFExtract(derived_secret, shared_secret, hasher)

        #print(hasher.length)
        self.secret["client"] = client_secret = crypto.HKDFExpandLabel(handshake_secret, "c hs traffic", hello_hash, hasher.length, hasher)
        self.secret["server"] = server_secret = crypto.HKDFExpandLabel(handshake_secret, "s hs traffic", hello_hash, hasher.length, hasher)

        self.handshake_key["client"] = [*crypto.HKDFExpandLabel(client_secret, "key", "", 32, hasher)]
        self.handshake_key["server"] = [*crypto.HKDFExpandLabel(server_secret, "key", "", 32, hasher)]
        self.handshake_iv["client"] = [*crypto.HKDFExpandLabel(client_secret, "iv", "", 12, hasher)]
        self.handshake_iv["server"] = [*crypto.HKDFExpandLabel(server_secret, "iv", "", 12, hasher)]

    def generate_application_secrets(self):
        hasher = self.cipher_suite.hash_algorithm
        empty_hash = hasher.hash("")

        transcript_msgs = []
        for msg in self.all_cache:
            if msg.child_id == 22:
                transcript_msgs.append(msg)

        handshake_hash = self.transcript_hash_msgs(transcript_msgs[:-1], hasher)
        derived_secret = crypto.HKDFExpandLabel(self.handshake_secret, "derived", empty_hash, hasher.length, hasher)
        master_secret = crypto.HKDFExtract(derived_secret, b"\0"*hasher.length, hasher)

        #print(hasher.length)
        self.secret["client"] = client_secret = crypto.HKDFExpandLabel(master_secret, "c ap traffic", handshake_hash, hasher.length, hasher)
        self.secret["server"] = server_secret = crypto.HKDFExpandLabel(master_secret, "s ap traffic", handshake_hash, hasher.length, hasher)

        self.application_key["client"] = [*crypto.HKDFExpandLabel(client_secret, "key", "", 32, hasher)]
        self.application_key["server"] = [*crypto.HKDFExpandLabel(server_secret, "key", "", 32, hasher)]
        self.application_iv["client"] = [*crypto.HKDFExpandLabel(client_secret, "iv", "", 12, hasher)]
        self.application_iv["server"] = [*crypto.HKDFExpandLabel(server_secret, "iv", "", 12, hasher)]

    def decrypt_message(self, record: TLSRecordFrame, key:list, iv:list):
        key = key
        iv = iv

        # https://datatracker.ietf.org/doc/html/rfc8446#section-5.2
        # https://datatracker.ietf.org/doc/html/rfc8446#section-5.3
        recnum = [0] * (len(iv) - 8) + int_to_list(self.record_num["server"], 8)
        nonce = [iv[i] ^ recnum[i] for i in range(len(iv))]

        if self.cipher_suite.type_id in (0x1301, 0x1302):
            decrypter = crypto.AESGCM(bytes(key))
        else:
            raise RuntimeError("Unsupported")

        additional_data = record.get_binary()[:5]

        # https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM.decrypt
        decrypted_data = decrypter.decrypt(bytes(nonce), bytes(record.child.encrypted_data), bytes(additional_data))

        record.child.raw_data = [*decrypted_data]

    def encrypt_message(self, record: TLSRecordFrame, key:list, iv:list):
        key = key
        iv = iv

        raw_data = record.get_binary()
        #print(raw_data)

        # https://datatracker.ietf.org/doc/html/rfc8446#section-5.2
        # https://datatracker.ietf.org/doc/html/rfc8446#section-5.3
        recnum = [0] * (len(iv) - 8) + int_to_list(self.record_num["client"], 8)
        nonce = [iv[i] ^ recnum[i] for i in range(len(iv))]

        if self.cipher_suite.type_id in (0x1301, 0x1302):
            encrypter = crypto.AESGCM(bytes(key))
        else:
            raise RuntimeError("Unsupported")

        additional_data = raw_data[:5]

        # https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM.decrypt
        encrypted_data = encrypter.encrypt(bytes(nonce), bytes(raw_data[5:] + [record.child_id]), bytes(additional_data))

        #print(len([*encrypted_data]))

        additional_data = [23, 3, 3] + int_to_list(len(encrypted_data), 2)

        encrypted_data = encrypter.encrypt(bytes(nonce), bytes(raw_data[5:] + [record.child_id]), bytes(additional_data))

        result = TLSRecordFrame(
            TLSCiphertext(
                TLSInnerPlaintext.parse(raw_data[5:] + [record.child_id]),
                [*encrypted_data]
            )
        )

        result.tls_version = 0x0303

        #self.decrypt_message(result, key, iv)

        return result

    def check_certificate_verify(self, certificate_verify: TLSCertificateVerifyFrame, certificate):
        public_key = certificate.public_key()
        signature = bytes(certificate_verify.signature)

        transcript_msgs = []
        for msg in self.all_cache:
            if msg.child.child == certificate_verify:
                break
            transcript_msgs.append(msg)

        content = self.transcript_hash_msgs(transcript_msgs, self.cipher_suite.hash_algorithm)

        signature_source = b"\x20" * 64 + b"TLS 1.3, server CertificateVerify" + b"\0" + content

        public_key.verify(signature, signature_source, self.signature_scheme.signature_algorithm.algorithm)

    def check_server_finished(self, finished):
        hasher = self.cipher_suite.hash_algorithm

        finished_key = crypto.HKDFExpandLabel(self.secret["server"], "finished", "", hasher.length, hasher)

        transcript_msgs = []
        for msg in self.all_cache:
            if msg.child.child == finished:
                break
            transcript_msgs.append(msg)

        finished_hash = self.transcript_hash_msgs(transcript_msgs, hasher)

        verify_data = hasher.hmac(finished_key, finished_hash)

        if bytes(finished.verify_data) != verify_data:
            raise RuntimeError("Verify Failed")

        return True

    def generate_client_finished_data(self):
        hasher = self.cipher_suite.hash_algorithm

        finished_key = crypto.HKDFExpandLabel(self.secret["client"], "finished", "", hasher.length, hasher)

        transcript_msgs = self.all_cache

        finished_hash = self.transcript_hash_msgs(transcript_msgs, hasher)

        verify_data = hasher.hmac(finished_key, finished_hash)
        #print([*verify_data])

        return verify_data

    def connect(self, address:str, port:int):
        if self.phase != 0:
            return
        if self.isconnected:
            raise RuntimeError("Already connected")
        self.sock = socket.create_connection((address, port))
        self._isconnected = True

    def close(self, raise_exception=False):
        if self.phase not in (-1, 0, 1):
            if self.phase == 8:
                alert = TLSAlertFrame(1, 0)
            else:
                alert = TLSAlertFrame(2, 90)
            self.raw_send(
                TLSRecordFrame(
                    alert
                )
            )
            if alert.level == 1:
                while True:
                    packet = self.raw_recv(recv_alert=True)
                    if packet.child_id == 21 and (packet.child.description in (0,) or packet.child.level == 2):
                        break
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
        client_hello.cipher_suites.append(TLSCipherSuite(0x1302)) # TLS_AES_256_GCM_SHA384
        client_hello.extensions.append(
            ext.client.client_hello.TLSSupportedVersionsExtension([TLSVersion("1.3")])
        ) # supported versions
        client_hello.extensions.append(
            ext.client.client_hello.TLSSignatureAlgorithmsExtension([SignatureScheme(0x0403)])
        ) # signature algorithms
        client_hello.extensions.append(
            ext.client.client_hello.TLSSupportedGroupsExtension([NamedGroup(0x001d)])
        ) # supported groups ecdhe x25195
        client_hello.extensions.append(
            ext.client.client_hello.TLSKeyShareExtension([
                KeyShareEntry(NamedGroup(0x001d), self.public_key["client"])
            ])
        ) # key share

        server_hello = None

        while self.phase in (0, 2):
            self.phase = 1

            self.raw_send(
                TLSRecordFrame(
                    TLSHandshakeFrame(
                        client_hello
                    )
                )
            )

            self.phase = 2

            server_hello = self.raw_recv()

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

        self.cipher_suite = server_hello.cipher_suite

        for extension in server_hello.extensions:
            if extension.type_id == 51:
                if extension.entry.group.group_id == 0x001d: # X25519, must always True
                    self.public_key["server"] = crypto.PublicKey(extension.entry.key.value, crypto.X25519)
                    self.shared_key = self.private_key["client"].exchange(self.public_key["server"])

        if self.shared_key == None:
            raise RuntimeError("Could not get shared key")

        self.generate_handshake_secrets()

        encrypted_extensions = None
        recv_change_cipher_spec = False # for compatibility
        while self.phase == 3:
            encrypted_extensions = self.raw_recv()
            if encrypted_extensions.child_id == 20 and recv_change_cipher_spec == False:
                recv_change_cipher_spec = True
                continue
            if encrypted_extensions.child_id == 22 and encrypted_extensions.child.child_id == 8:
                self.phase = 4
                encrypted_extensions = encrypted_extensions.child.child
            else:
                raise RuntimeError("Illegal message!")

        certificate_message = self.raw_recv()
        if certificate_message.child_id != 22 or certificate_message.child.child_id != 11:
            raise RuntimeError("Illegal message!")

        certificate_message = certificate_message.child.child

        certs = []
        for cert_entry in certificate_message.certificates:
            certs.append(cert_entry.certificate)
            #print(cert_entry.extensions)
        #print(certs)

        crypto.verify_certificates(certs[0], certs[1:])

        certificate_verify = self.raw_recv()
        if certificate_verify.child_id != 22 or certificate_verify.child.child_id != 15:
            raise RuntimeError("Illegal message!")

        certificate_verify = certificate_verify.child.child

        self.signature_scheme = certificate_verify.signature_scheme

        self.check_certificate_verify(certificate_verify, certs[0])

        server_finished = self.raw_recv()

        if server_finished.child_id != 22 or server_finished.child.child_id != 20:
            raise RuntimeError("Illegal message!")

        server_finished = server_finished.child.child

        self.check_server_finished(server_finished)

        self.raw_send(
            TLSRecordFrame(
                TLSHandshakeFrame(
                    TLSFinishedFrame(
                        self.generate_client_finished_data()
                    )
                )
            )
        )

        self.generate_application_secrets()
        self.record_num["client"] = self.record_num["server"] = 0

        self.phase = 8


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
