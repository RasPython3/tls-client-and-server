import secrets

def int_to_list(intValue, length):
    result = []
    for i in range(length):
        result.append((intValue // (0x100 ** (length - i - 1))) % 0x100)
    return result

def gen_random(length: int):
    return [int(i) for i in secrets.token_bytes(length)]

