from .. import core
from ...utils import int_to_list
from ...common import TLSVersion, KeyShareEntry, SignatureSchemeList, NamedGroup


class TLSSupportedVersionsExtension(core.TLSExtension):
    def __init__(self, versions:list=[]):
        super().__init__(43)
        for version in versions:
            if not isinstance(version, TLSVersion):
                raise TypeError("A version must be TLSVersion")
        self.versions = versions

    @property
    def data(self):
        return int_to_list(len(self.versions)*2, 1) + sum([int_to_list(version.value, 2) for version in self.versions], [])

    @data.setter
    def data(self, value):
        pass

    @classmethod
    def parse(cls, data: list):
        if len(data) == 0:
            raise RuntimeError("Illegal length")
        length = data[0]
        index = 1
        versions = []
        while index-1 < length:
            if index+1 > length:
                raise RuntimeError("Illegal length")
            versions.append(TLSVersion(data[index] * 0x100 + data[index+1]))
            index += 2
        return cls(versions)

class TLSSupportedGroupsExtension(core.TLSExtension):
    def __init__(self, groups:list=[]):
        super().__init__(10)
        if any([not isinstance(group, NamedGroup) for group in groups]):
            raise TypeError('Invalid NamedGroup')
        self.groups = groups

    @property
    def data(self):
        return int_to_list(len(self.groups)*2, 2) + sum([group.get_binary() for group in self.groups], [])

    @data.setter
    def data(self, value):
        pass

    @classmethod
    def parse(cls, data: list):
        if len(data) == 0:
            return RuntimeError("Illegal length")
        length = data[0] * 0x100 + data[1]
        index = 2
        groups = []
        while index < length+2:
            if index+2 > length+2:
                return RuntimeError("Illegal length")
            groups.append(NamedGroup.parse(data[index:index+2]))
            index += 2
        return cls(groups)
        


class TLSSignatureAlgorithmsExtension(core.TLSExtension):
    def __init__(self, schemes:list):
        super().__init__(13)
        if isinstance(schemes, (list, tuple)):
            if isinstance(schemes, SignatureSchemeList):
                self.schemes = schemes
            else:
                self.schemes = SignatureSchemeList(*schemes)
        else:
            raise TypeError("schemes is not an instance of list, tuple or SignatureSchemeList")
    
    @property
    def data(self):
        return self.schemes.get_binary()

    @data.setter
    def data(self, value):
        pass

    @classmethod
    def parse(cls, data: list):
        return cls(SignatureSchemeList.parse(data))

class TLSKeyShareExtension(core.TLSExtension):
    def __init__(self, entries:list):
        super().__init__(51)
        if any([not isinstance(entry, KeyShareEntry) for entry in entries]):
            raise TypeError("some of given entries are not KeyShareEntry")
        self.entries = entries

    @property
    def data(self):
        result = []
        for entry in self.entries:
            result.extend(entry.get_binary())
        return int_to_list(len(result), 2) + result

    @data.setter
    def data(self, value):
        pass

    @classmethod
    def parse(cls, data: list):
        if len(data) - 2 != data[0] * 0x100 + data[1]:
            raise RuntimeError("Illegal length")
        index = 2
        data_length = len(data)
        entries = []
        while index < data_length:
            if index+4 > data_length:
                raise RuntimeError("Illegal length")
            length = data[index+2] * 0x100 + data[index+3]
            if index+4+length > data_length:
                raise RuntimeError("Illegal length")
            entries.append(KeyShareEntry.parse(data[index:index+length+4]))
            index += length + 4
        return cls(entries)
