from Crypto.Cipher import AES

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
        blocksize = 16
        tests = {}
        for i in range(0, len(raw) // blocksize):
            subblock = raw[i * blocksize:(i + 1) * blocksize]
            string = conv.bytes_to_hex(subblock)
            if string in tests:
                return line
            tests[string] = True
            
    return "No repeating blocks in any ciphertexts"

def chunks(l, n):
    return [l[i:i+n] for i in range(0, len(l), n)]

def padded(block, size):
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


def encrypt_cbc(input, key, iv):
    blocksize = 16
    last = iv
    output = bytearray()
    blocks = chunks(input, blocksize)
    for block in blocks:
        if len(block) < blocksize:
            block = padded(block, blocksize)
        combined = xor_bytes(last, block)
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

