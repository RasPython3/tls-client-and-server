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
        self.send("GET /index.html HTTP/1.1\r\nHost: github.com\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n")
        print(bytes(self.recv()).decode("utf-8"))

if __name__ == "__main__":
    app = HttpClient()
    app.run("172.23.91.188", 8080)