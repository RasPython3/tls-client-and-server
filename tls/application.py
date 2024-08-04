from .client import Client
from .server import Server

class ApplicationType:
    CLIENT = 0
    SERVER = 1

class Application:
    def __init__(self, app_type: ApplicationType):
        self.app_type = app_type
        if app_type == ApplicationType.CLIENT:
            self.tls_app = Client()
        elif app_type == ApplicationType.SERVER:
            self.tls_app = Server()
        else:
            raise RuntimeError("Unsupported application type")

        self.is_running = False

    def start(self, url: str, port: int):
        if self.app_type == ApplicationType.CLIENT:
            self.tls_app.connect(url, port)
            self.tls_app.handshake()
        else:
            self.tls_app.listen(url, port)
            self.tls_app.handshake()

    def end(self):
        self.tls_app.close()

    def main(self):
        pass

    def send(self, *args, **kwargs):
        return self.tls_app.send(*args, **kwargs)

    def recv(self, *args, **kwargs):
        return self.tls_app.recv(*args, **kwargs)

    def run(self, url: str, port: int):
        self.start(url, port)

        self.main()

        self.end()