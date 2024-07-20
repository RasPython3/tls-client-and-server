from tls.application import Application, ApplicationType

class Pinger(Application):
    def __init__(self):
        super().__init__(ApplicationType.CLIENT)

    def main(self):
        self.send("ping")

        print(self.recv())

class HttpClient(Application):
    def __init__(self):
        super().__init__(ApplicationType.CLIENT)

    def main(self):
        self.send("GET /index.html HTTP/1.1\r\nHost: 127.0.0.1:50000\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n")
        self.recv()

if __name__ == "__main__":
    app = HttpClient()
    app.run("127.0.0.1", 50000)