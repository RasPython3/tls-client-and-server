from ..base import TLSHandshakeFrame

class TLSFinishedFrame(TLSHandshakeFrame):
    def __init__(self, data):
        super().__init__()
        self.type_id = 0x14
        self.verify_data = data

    @classmethod
    def parse(cls, data: list):
        return cls(data)

    def get_binary(self):
        return self.verify_data