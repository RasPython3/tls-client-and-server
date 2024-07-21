from .. import core
from ...utils import int_to_list
from ...common import TLSVersion, KeyShareEntry


class TLSSupportedVersionsExtension(core.TLSExtension):
    def __init__(self, version:TLSVersion):
        super().__init__(43)
        if not isinstance(version, TLSVersion):
            raise TypeError("A version must be TLSVersion")
        self.version = version

    @property
    def data(self):
        return int_to_list(self.version.value, 2)

    @data.setter
    def data(self, value):
        pass

    @classmethod
    def parse(cls, data: list):
        if len(data) != 2:
            return RuntimeError("Illegal length")

        return cls(TLSVersion(data[0] * 0x100 + data[1]))

class TLSKeyShareExtension(core.TLSExtension):
    def __init__(self, entry:KeyShareEntry):
        super().__init__(51)
        if not isinstance(entry, KeyShareEntry):
            raise TypeError("given entry is not KeyShareEntry")
        self.entry = entry

    @property
    def data(self):
        result = self.entry.get_binary()
        return result

    @data.setter
    def data(self, value):
        pass

    @classmethod
    def parse(cls, data: list):
        entry = KeyShareEntry.parse(data)
        return cls(entry)
