import socket

class BaseSocket(object):
    def sendlist(self, data:list):
        bytesdata = bytes(list)
        return self.send(bytesdata)

    def recvlist(self, length):
        return self.recv(length)

class TLSSocket(BaseSocket):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.cache = []

    def recvtls(self):
        tls_type = -1
        tls_length = -1
        tls_results = BaseTLSFrame()
        data = [*self.cache]
        self.cache = []
        
        buffer_size = 5 # TLS header
        while tls_length < 0 or len(data) < 5 + tls_length:
            data.expand(self.recvlist(buffer_size))

            if tls_length < 0 and len(data) >= 5:
                tls_type = data[0]
                tls_length = data[3] * 0xff + data[4]
                buffer_size = tls_length - len(data) + 5
        
        self.cache.expand(data[tls_length+5])

        pass

