from Crypto.Cipher import AES
import random

import conv
import xortools

def decrypt_ecb(input, key):
    aes = AES.new(key, AES.MODE_ECB)
    return bytes(strippadding(bytearray(aes.decrypt(input))))

def encrypt_ecb(input, key):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(padded(input))

def find_aes(file):
    for line in file:
        line = line.rstrip()
        raw = conv.hex_to_bytes(line)
        if detect_repeat(raw):
            return line

def detect_repeat(raw):
    blocksize = 16
    tests = {}
    for i in range(0, len(raw) // blocksize):
        subblock = raw[i * blocksize:(i + 1) * blocksize]
        string = conv.bytes_to_hex(subblock)
        if string in tests:
            return True
        tests[string] = True

    return False

def chunks(l, n):
    return [l[i:i+n] for i in range(0, len(l), n)]

def padded(block, size=16):
    remainder_bytes = len(block) % size
    if(remainder_bytes == 0):
        return block

    paddedblock = bytearray(block)
    for i in range(size - remainder_bytes):
        paddedblock.append(4)

    return bytes(paddedblock)

def strippadding(b):
    while b[-1] == 4:
        b.pop()
    return b

def random_key(length):
    output = bytearray()

    for i in range(0, length):
        # TODO obviously this isn't secure, i'm sure that comes up later
        output.append(random.randint(0, 255))

    return bytes(output)

def encrypt_cbc(input, key, iv):
    blocksize = 16
    last = iv
    output = bytearray()
    blocks = chunks(input, blocksize)
    for block in blocks:
        if len(block) < blocksize:
            block = padded(block, blocksize)
        combined = xortools.xor_bytes(last, block)
        encrypted = encrypt_ecb(combined, key)
        output.extend(encrypted)
        last = encrypted
    return output

def decrypt_cbc(input, key, iv):
    blocksize = 16
    last = iv
    output = bytearray()
    blocks = chunks(input, blocksize)
    for block in blocks:
        decrypted = decrypt_ecb(bytes(block), key)
        combined = xortools.xor_bytes(last, decrypted)
        output.extend(combined)
        last = block
    return bytes(strippadding(output))

def encryption_oracle(input):
    key = random_key(16)
    input_fixed = add_bytes_to_input(input)
    
    if(random.random() >= 0.5):
        return encrypt_ecb(input_fixed, key), "ECB"
    else:
        return encrypt_cbc(input_fixed, key, random_key(16)), "CBC"

def add_bytes_to_input(input):
    output = bytearray()
    bytes_before = random.randint(5, 10)
    bytes_after = random.randint(5, 10)
    output.extend(random_key(bytes_before))
    output.extend(input)
    output.extend(random_key(bytes_after))
    return bytes(output)

def detect_mode(encrypted):
    return "ECB" if detect_repeat(encrypted) else "CBC"

BLACK_BOX_KEY = random_key(16)
TEXT = """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""
def black_box(input):
    combined = bytearray()
    combined.extend(input)
    combined.extend(conv.base_64_to_bytes(TEXT))
    # input_fixed = add_bytes_to_input(input)
    return encrypt_ecb(bytes(combined), BLACK_BOX_KEY)

def get_block_size_and_length(blackbox):
    test = bytearray()
    blocksize = None
    last_length = None
    while(blocksize is None):
        test.append(65)
        encrypted = blackbox(bytes(test))
        new_length = len(encrypted)
        if(last_length is not None and new_length > last_length):
            blocksize = new_length - last_length
            break
        last_length = new_length
    return (blocksize, last_length)

def break_ECB(blocksize, length, blackbox):
    one_short = bytearray(bytes(length - 1))
    for i in range(0, length):
        dictionary = {}
        for b in range(256):
            one_short.append(b)
            output = blackbox(bytes(one_short))
            test_block = output[length-blocksize : length]
            dictionary[test_block] = b
            one_short.pop()

        output = blackbox(bytes(one_short[0:length-i]))
        test_block = output[length-blocksize : length]
        found_byte = dictionary[test_block]
        one_short.pop(0)
        one_short.append(found_byte)

    return strippadding(one_short)

def break_ECB_1_byte(function):
    blocksize, length = get_block_size_and_length(function)
    mode = detect_mode(function(bytes(128)))
    if(mode != "ECB"):
        raise Exception("Black box not using ECB encryption")
    return break_ECB(blocksize, length, function)

