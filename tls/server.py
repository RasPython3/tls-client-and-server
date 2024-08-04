import socket
import secrets
import re

from . import crypto, ext

from .common import TLSVersion, CipherSuite, SignatureScheme, NamedGroup, KeyShareEntry, CertificateEntry

from .frames import NetworkFrame, TLSParentFrame, TLSRecordFrame, TLSInnerPlaintext, TLSCiphertext, TLSHandshakeFrame, TLSApplicationDataFrame, TLSAlertFrame, \
    TLSClientHelloFrame, TLSServerHelloFrame, TLSHelloRetryRequestFrame, TLSEncryptedExtensionsFrame, TLSCertificateFrame, TLSCertificateVerifyFrame, TLSFinishedFrame

from .utils import gen_random, int_to_list



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


class Server:
    def __init__(self, *, version=TLSVersion("1.3")):
        if version != TLSVersion("1.3"):
            raise RuntimeError("Only TLS 1.3 is supported")
        self.version = version
        self.sock = None
        self.conn = None
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
        self.signature_scheme = None

        self.certificates = []
        with open("/".join(re.split("[/\\\\]", __file__)[:-1]) + "/servercert.pem", mode="rb") as f:
            self.certificates.append(crypto.load_pem_x509_certificate(f.read()))

        with open("/".join(re.split("[/\\\\]", __file__)[:-1]) + "/serverkey.pem", mode="rb") as f:
            self.cert_private_key = crypto.load_pem_private_key(f.read(), None)

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
                        self.handshake_key["server"],
                        self.handshake_iv["server"]
                    )
                else: # Application
                    data = self.encrypt_message(
                        data,
                        self.application_key["server"],
                        self.application_iv["server"]
                    )
            self.record_num["server"] += 1
        return self.conn.send(bytes(data.get_binary()))

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
                data.extend(self.conn.recv(buffer_size))

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
                    self.decrypt_message(result, self.handshake_key["client"], self.handshake_iv["client"])
                else:
                    self.decrypt_message(result, self.application_key["client"], self.application_iv["client"])
                self.record_num["client"] += 1
                plaintext = TLSInnerPlaintext.parse(result.child.raw_data)
                #print([plaintext.content_type] + \
                #    int_to_list(result.tls_version, 2) + \
                #    int_to_list(len(plaintext.content), 2))
                #print(plaintext.content)
                result = TLSRecordFrame.parse(
                    [plaintext.content_type] + \
                    int_to_list(result.tls_version.value, 2) + \
                    int_to_list(len(plaintext.content), 2) + \
                    plaintext.content,
                    possibly_encrypted=False
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

            self.received_frames.append(result)

            print_tree(result, 0)

            if (plaintext == None and data[:tls_length+5] != result.get_binary()) or \
                (plaintext != None and plaintext.content != result.child.get_binary()):
                print("decode-then-encode failed")
                al = data[:tls_length+5]
                bl = result.get_binary()
                print("original = {}\n\nreencoded = {}".format(str(al), str(bl)))
                cl = []
                for i in range(max(len(al), len(bl))):
                    if len(al) > i:
                        if len(bl) > i:
                            cl.append(al[i] - bl[i])
                        else:
                            cl.append(al[i])
                    else:
                        cl.append(-bl[i])

                print(cl)


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
            raise RuntimeError("The client returned fatal alert: " + self.received_alert.get_description_text())

    def transcript_hash_msgs(self, msgs, hasher) -> bytes:
        data = []
        print(msgs)
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
        return crypto.transcript_hash([i.child for i in data], hasher)

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

        if self.cipher_suite.type_id in (0x1301,):
            self.handshake_key["client"] = [*crypto.HKDFExpandLabel(client_secret, "key", "", 16, hasher)]
            self.handshake_key["server"] = [*crypto.HKDFExpandLabel(server_secret, "key", "", 16, hasher)]
            self.handshake_iv["client"] = [*crypto.HKDFExpandLabel(client_secret, "iv", "", 12, hasher)]
            self.handshake_iv["server"] = [*crypto.HKDFExpandLabel(server_secret, "iv", "", 12, hasher)]
        elif self.cipher_suite.type_id in (0x1302,):
            self.handshake_key["client"] = [*crypto.HKDFExpandLabel(client_secret, "key", "", 32, hasher)]
            self.handshake_key["server"] = [*crypto.HKDFExpandLabel(server_secret, "key", "", 32, hasher)]
            self.handshake_iv["client"] = [*crypto.HKDFExpandLabel(client_secret, "iv", "", 12, hasher)]
            self.handshake_iv["server"] = [*crypto.HKDFExpandLabel(server_secret, "iv", "", 12, hasher)]
        else:
            raise RuntimeError("Could not generate secrets")

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

        if self.cipher_suite.type_id in (0x1301,):
            self.application_key["client"] = [*crypto.HKDFExpandLabel(client_secret, "key", "", 16, hasher)]
            self.application_key["server"] = [*crypto.HKDFExpandLabel(server_secret, "key", "", 16, hasher)]
            self.application_iv["client"] = [*crypto.HKDFExpandLabel(client_secret, "iv", "", 12, hasher)]
            self.application_iv["server"] = [*crypto.HKDFExpandLabel(server_secret, "iv", "", 12, hasher)]
        elif self.cipher_suite.type_id in (0x1302,):
            self.application_key["client"] = [*crypto.HKDFExpandLabel(client_secret, "key", "", 32, hasher)]
            self.application_key["server"] = [*crypto.HKDFExpandLabel(server_secret, "key", "", 32, hasher)]
            self.application_iv["client"] = [*crypto.HKDFExpandLabel(client_secret, "iv", "", 12, hasher)]
            self.application_iv["server"] = [*crypto.HKDFExpandLabel(server_secret, "iv", "", 12, hasher)]
        else:
            raise RuntimeError("Could not generate secrets")

    def decrypt_message(self, record: TLSRecordFrame, key:list, iv:list):
        key = key
        iv = iv

        # https://datatracker.ietf.org/doc/html/rfc8446#section-5.2
        # https://datatracker.ietf.org/doc/html/rfc8446#section-5.3
        recnum = [0] * (len(iv) - 8) + int_to_list(self.record_num["client"], 8)
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
        recnum = [0] * (len(iv) - 8) + int_to_list(self.record_num["server"], 8)
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
            ),
            version=TLSVersion("1.2")
        )

        #self.decrypt_message(result, key, iv)

        return result

    def generate_certificate_verify(self, certificate):
        private_key = self.cert_private_key

        transcript_msgs = []
        for msg in self.all_cache:
            transcript_msgs.append(msg)

        content = self.transcript_hash_msgs(transcript_msgs, self.cipher_suite.hash_algorithm)

        signature_source = b"\x20" * 64 + b"TLS 1.3, server CertificateVerify" + b"\0" + content

        return [*self.signature_scheme.signature_algorithm.derive(private_key, signature_source)]

    def check_client_finished(self, finished):
        hasher = self.cipher_suite.hash_algorithm

        finished_key = crypto.HKDFExpandLabel(self.secret["client"], "finished", "", hasher.length, hasher)

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

    def generate_server_finished_data(self):
        hasher = self.cipher_suite.hash_algorithm

        finished_key = crypto.HKDFExpandLabel(self.secret["server"], "finished", "", hasher.length, hasher)

        transcript_msgs = self.all_cache

        finished_hash = self.transcript_hash_msgs(transcript_msgs, hasher)

        verify_data = hasher.hmac(finished_key, finished_hash)
        #print([*verify_data])

        return verify_data

    def listen(self, url:str, port:int):
        if self.phase != 0:
            return
        if self.isconnected:
            raise RuntimeError("Already connected")
        self.sock = socket.create_server((url, port))
        self._isconnected = True
        self.sock.listen(1)

        self.conn, addr = self.sock.accept()

    def close(self, raise_exception=False):
        if self.phase not in (-1, 0, 1):
            if self.phase == 8:
                alert = TLSAlertFrame(1, 0)
            else:
                alert = TLSAlertFrame(2, 80)
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
            self.conn.close()
            self.sock.close()
            self.sock.shutdown(socket.SHUT_RD)
            return True
        except Exception as e:
            if raise_exception:
                raise e
            return False

    def handshake(self):
        self.check_connected()

        server_random = self.random["server"] = gen_random(32)

        self.shared_key = None

        self.phase = 1

        client_hello = self.raw_recv()

        if client_hello.child_id != 22 or client_hello.child.child_id != 0x01:
            raise RuntimeError("Illegal message!")

        self.phase = 2

        client_hello = client_hello.child.child

        if all([extension.type_id != 43 for extension in client_hello.extensions]):
            raise RuntimeError("Could not negotiate with TLS 1.3")

        if all([type_id not in [cipher_suite.type_id for cipher_suite in client_hello.cipher_suites] for type_id in (0x1301, 0x1302)]):
            raise RuntimeError("No supported CipherSuite!")

        if 0x1302 in [cipher_suite.type_id for cipher_suite in client_hello.cipher_suites]:
            self.cipher_suite = CipherSuite(0x1302)
        else:
            self.cipher_suite = CipherSuite(0x1301)

        for extension in client_hello.extensions:
            if extension.type_id == 51:
                for entry in extension.entries:
                    if entry.group.group_id == 0x001d: # X25519, must always True
                        group_id = 0x001d
                        self.private_key["server"] = crypto.PrivateKey.generate(0x001d)
                        self.public_key["server"] = crypto.PublicKey.from_private(self.private_key["server"])
                        self.public_key["client"] = crypto.PublicKey(entry.key.value, crypto.X25519)
                        self.shared_key = self.private_key["server"].exchange(self.public_key["client"])
            elif extension.type_id == 13:
                if 0x0403 in [scheme.sig_id for scheme in extension.schemes]:
                    self.signature_scheme = SignatureScheme(0x0403)

        if self.shared_key == None:
            raise RuntimeError("Could not get shared key")

        if self.signature_scheme == None:
            raise RuntimeError("No supported Signature Scheme")

        server_hello = TLSServerHelloFrame(
            TLSVersion("1.2"),
            server_random,
            client_hello.legacy_session_id,
            self.cipher_suite,
            [
                ext.ServerHelloExtensions.SupportedVersions(TLSVersion("1.3")),
                ext.ServerHelloExtensions.KeyShare(
                    KeyShareEntry(NamedGroup(group_id), self.public_key["server"])
                )
            ]
        )

        self.raw_send(
            TLSRecordFrame(
                TLSHandshakeFrame(
                    server_hello
                )
            )
        )

        self.generate_handshake_secrets()

        self.phase = 3

        encrypted_extensions = TLSEncryptedExtensionsFrame()

        self.raw_send(
            TLSRecordFrame(
                TLSHandshakeFrame(
                    encrypted_extensions
                )
            )
        )

        certificate_message = TLSCertificateFrame([], [CertificateEntry(cert, []) for cert in self.certificates])

        self.raw_send(
            TLSRecordFrame(
                TLSHandshakeFrame(
                    certificate_message
                )
            )
        )

        certificate_verify = TLSCertificateVerifyFrame(
            self.signature_scheme,
            self.generate_certificate_verify(
                self.certificates[0]
            )
        )

        self.raw_send(
            TLSRecordFrame(
                TLSHandshakeFrame(
                    certificate_verify
                )
            )
        )

        self.raw_send(
            TLSRecordFrame(
                TLSHandshakeFrame(
                    TLSFinishedFrame(
                        self.generate_server_finished_data()
                    )
                )
            )
        )

        client_finished = self.raw_recv()

        if client_finished.child_id != 22 or client_finished.child.child_id != 20:
            raise RuntimeError("Illegal message!")

        client_finished = client_finished.child.child

        self.check_client_finished(client_finished)

        self.generate_application_secrets()
        self.record_num["client"] = self.record_num["server"] = 0

        self.phase = 8
