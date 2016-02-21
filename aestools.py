from Crypto.Cipher import AES
import random

import conv
import xortools

def decrypt_ecb(input, key):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.decrypt(input)

def encrypt_ecb(input, key):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(input)

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
    paddedblock = bytearray()
    for i in range(size):
        if i < len(block):
            paddedblock.append(block[i])
        else:
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
        return encrypt_ecb(input, key), "ECB"
    else:
        return encrypt_cbc(input, key, random_key(16)), "CBC"

def add_bytes_to_input(input):
    output = bytearray()
    bytes_before = random.randint(5, 10)
    bytes_after = random.randint(5, 10)
    output.extend(random_key(bytes_before))
    output.extend(input)
    output.extend(random_key(bytes_after))
    return output

def detect_mode(encrypted):
    return "ECB" if detect_repeat(encrypted) else "CBC"

    
