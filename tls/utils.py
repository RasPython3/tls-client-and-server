import secrets
from . import common

def int_to_list(intValue, length):
    result = []
    for i in range(length):
        result.append((intValue // (0x100 ** (length - i - 1))) % 0x100)
    return result

def gen_random(length: int):
    return [int(i) for i in secrets.token_bytes(length)]


def print_tree(data):
    target = data
    indent = 0
    while isinstance(target, common.NetworkFrame):
        print("  " * indent + target.__class__.__name__)
        if isinstance(target, common.TLSParentFrame):
            target = target.child
            indent += 1
        else:
            break

