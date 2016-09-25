from Crypto.Cipher import AES
import os
import random

import conv
import xortools

class InvalidPaddingException(Exception):
    pass

def decrypt_ecb(input, key, padded=False):
    aes = AES.new(key, AES.MODE_ECB)
    decrypted = aes.decrypt(input)
    if(padded):
        return strip_valid_padding(decrypted)
    else:
        return decrypted

def encrypt_ecb(input, key, pad=False):
    aes = AES.new(key, AES.MODE_ECB)
    if(pad):
        input = padded(input)
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

def padded(input, blocksize=16):
    padding_needed = blocksize - len(input) % blocksize
    paddedblock = bytearray(input)
    # the byte used for padding is equal to the amount of padding (PKCS-7)
    for i in range(padding_needed):
        paddedblock.append(padding_needed)

    return bytes(paddedblock)

def strip_valid_padding(b):
    b = bytearray(b)
    padding_byte = b[-1]
    if(padding_byte not in range(1, 17)):
        raise InvalidPaddingException("Invalid padding")

    for i in range(padding_byte):
        popped_byte = b.pop()
        if(popped_byte != padding_byte):
            raise InvalidPaddingException("Invalid padding")
    return bytes(b)

def random_key(length):
    return bytes(os.urandom(length))

def encrypt_cbc(input, key, iv):
    blocksize = 16
    last = iv
    output = bytearray()
    input = padded(input, blocksize)
    blocks = chunks(input, blocksize)
    for block in blocks:
        combined = xortools.xor_bytes(last, block)
        encrypted = encrypt_ecb(combined, key)
        output.extend(encrypted)
        last = encrypted
    return output

def decrypt_cbc(input, key, iv, strip=True):
    blocksize = 16
    last = iv
    output = bytearray()
    blocks = chunks(input, blocksize)
    for block in blocks:
        decrypted = decrypt_ecb(bytes(block), key)
        combined = xortools.xor_bytes(last, decrypted)
        output.extend(combined)
        last = block

    return strip_valid_padding(output) if strip else output

def encryption_oracle(input):
    key = random_key(16)
    input_fixed = add_bytes_to_input(input)
    
    if(random.random() >= 0.5):
        return encrypt_ecb(input_fixed, key, True), "ECB"
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
PREFIX_MAX = 64
PREFIX = bytes(random_key(random.randint(0, PREFIX_MAX)))
def get_black_box(prefix=False):
    return lambda input : black_box(input, prefix)

def black_box(input, prefix=False):
    combined = bytearray()
    if(prefix): combined.extend(PREFIX)
    combined.extend(input)
    combined.extend(conv.base_64_to_bytes(TEXT))
    return encrypt_ecb(bytes(combined), BLACK_BOX_KEY, True)

def get_block_size_and_length(blackbox):
    test = bytearray()
    blocksize = None
    last_length = None
    padding = 0
    while(blocksize is None):
        encrypted = blackbox(bytes(test))
        new_length = len(encrypted)
        if(last_length is not None and new_length > last_length):
            blocksize = new_length - last_length
            break
        last_length = new_length
        test.append(65)
        padding += 1
    return (blocksize, last_length, padding)

def get_prefix_length(blackbox, blocksize, length, padding):
    # TODO it said crazy math wasn't required, did i solve this the best way?

    # enough that there should be repeating blocks, but no padding at the end
    # this will actually make a full block of padding at the end now
    input_length = (blocksize * 3) + padding
    input = bytes(input_length)
    prefix_tester = blackbox(input)

    # if there's no prefix, the first two blocks should be identical in ECB mode
    has_prefix = prefix_tester[0 : blocksize] != prefix_tester[blocksize : 2*blocksize]
    if(not has_prefix):
        return 0
    last_num_repeating = 0
    prefix_size_padded = -1

    for delta in range(0, input_length):
        input = bytes(input_length - delta)
        prefix_tester = blackbox(input)
        num_repeating = 1
        last_block = bytes()
        # see how many blocks repeat with this test input
        for i in range(0, len(prefix_tester), blocksize):
            current_block = prefix_tester[i : i + blocksize]
            if(current_block == last_block):
                num_repeating += 1
                if(prefix_size_padded == -1):
                    prefix_size_padded = i - blocksize
            elif(num_repeating > 1):
                # when we stop seeing repeating blocks
                break
            last_block = current_block

        # if we found less repeating blocks this time, we found the length of the right side
        if(num_repeating < last_num_repeating):
            # we have the length of the target
            right_side = delta - 1
            left_side = padding - right_side

            # TODO don't really understand this, but it can be less than zero
            if(left_side < 0): left_side += blocksize

            return prefix_size_padded - left_side
        else:
            last_num_repeating = num_repeating
    return 0


def break_ECB(blocksize, length, padding, blackbox, prefix_length):
    length -= prefix_length
    one_short = bytearray(bytes(length - 1))

    for i in range(0, length - padding):
        dictionary = {}
        test_block_start = prefix_length + len(one_short) + 1 - blocksize
        for b in range(256):
            one_short.append(b)
            output = blackbox(bytes(one_short))
            test_block = output[test_block_start : test_block_start+blocksize]
            dictionary[test_block] = b
            one_short.pop()

        output = blackbox(bytes(one_short[0:length-i-1]))
        test_block = output[test_block_start : test_block_start+blocksize]
        found_byte = dictionary[test_block]
        one_short.pop(0)
        one_short.append(found_byte)

    return bytes(one_short[padding-1 : len(one_short)])

def break_ECB_rest(blocksize, length, blackbox):
    prefix = 'email='
    prefix_len = len(prefix)
    desired_email = 'gimmeadmin+@example.com'
    at_index = desired_email.index('@')

    # create enough bytes to get to the next block
    prefix_padding = bytearray()
    for i in range(prefix_len, blocksize):
        prefix_padding.append(65)

    # create an entire block with just admin and padding
    role_block = padded(b'admin')


    # encrypt and cut that admin block out for later use
    cut_encrypted = blackbox(prefix_padding + role_block)
    cut_block = cut_encrypted[blocksize : blocksize*2]

    # calculate the number of bytes needed to make it so 'user' is in its own final block
    length_minus_user = length - len('user')
    short_bytes = blocksize - (length_minus_user % blocksize)
    # don't forget to account for the 'email=' start and the desired email length
    short_bytes -= prefix_len + len(desired_email)
    # we can't take away bytes, so increment by the blocksize
    while(short_bytes < 0):
        short_bytes += blocksize

    # fill in the extra part of the email with padding to put the last block into position
    for i in range(short_bytes):
        desired_email = desired_email[0 : at_index] + 'a' + desired_email[at_index : len(desired_email)]
    email = bytearray(bytes(desired_email, 'ascii'))

    # get the actual encrypted cookie
    real_encrypted = blackbox(email)
    # pull off the last block which should be 'user0x0C0x0C...' and replace with our admin block
    pasted_encrypted = real_encrypted[0 : len(real_encrypted)-blocksize] + cut_block

    return pasted_encrypted

def break_ECB_1_byte(function):
    blocksize, length, padding = get_block_size_and_length(function)
    mode = detect_mode(function(bytes(128)))
    if(mode != "ECB"):
        raise Exception("Black box not using ECB encryption")
    prefix_length = get_prefix_length(function, blocksize, length, padding)
    return break_ECB(blocksize, length, padding, function, prefix_length)

def create_admin_profile(function):
    stringified_function = lambda the_bytes: function(str(the_bytes, 'UTF-8'))
    blocksize, length, padding = get_block_size_and_length(stringified_function)
    mode = detect_mode(stringified_function(bytes(128)))
    if(mode != "ECB"):
        raise Exception("Black box not using ECB encryption")
    return break_ECB_rest(blocksize, length, stringified_function)

CBC_START = 'comment1=cooking%20MCs;userdata='
CBC_END = ';comment2=%20like%20a%20pound%20of%20bacon'
CBC_IV = random_key(16)

def cbc_black_box(input):
    input = input.replace(';', '";"').replace('=', '"="')
    full_user_string = CBC_START + input + CBC_END
    return encrypt_cbc(bytes(full_user_string, 'ascii'), BLACK_BOX_KEY, CBC_IV)

def has_admin_string(input):
    decrypted = decrypt_cbc(input, BLACK_BOX_KEY, CBC_IV)
    return decrypted.find(b';admin=true;') >= 0

def bit_flip_cbc(function):
    blocksize, length, padding = get_block_size_and_length(lambda input : function(input.decode('ascii')))

    # TODO should i not know this?
    prefix_length = len(CBC_START)
    suffix_length = len(CBC_END)

    # bytes that are 1 bit away from the desired bytes
    semi_replacement = ':'
    equals_replacement = '<'

    # full block of nonsense before the admin block so we can flip bits the block before
    nonsense = 'aaaaaaaaaaaaaaaa'
    target = 'aaaaa' + semi_replacement + 'admin' + equals_replacement + 'true'
    encrypted = function(nonsense + target)

    # need to figure out indexes of the bytes to modify in the block before
    end_of_block_before = len(encrypted) - padding - suffix_length - blocksize
    semi_pos = end_of_block_before - (len(target) - target.find(semi_replacement))
    equals_pos = end_of_block_before - (len(target) - target.find(equals_replacement))
    semi_pos_byte = encrypted[semi_pos]
    equals_pos_byte = encrypted[equals_pos]

    #flip the first bit
    encrypted[semi_pos] = semi_pos_byte ^ 1
    encrypted[equals_pos] = equals_pos_byte ^ 1

    return encrypted

def provide_cbc_ecrypted():
    input_file = open('files/17.txt', 'r')
    lines = [line.rstrip() for line in input_file]
    input_file.close()
    line = lines[random.randint(0, len(lines) - 1)]
    return (encrypt_cbc(conv.base_64_to_bytes(line), BLACK_BOX_KEY, CBC_IV), CBC_IV)

def is_valid_padding(encrypted, iv):
    decrypted = decrypt_cbc(encrypted, BLACK_BOX_KEY, iv, False)
    try:
        stripped_padding = strip_valid_padding(decrypted)
        return True
    except InvalidPaddingException:
        return False

def break_cbc_using_padding(oracle, cipher, iv):
    cracked = bytearray()
    actual_iv = iv
    for target_start in range(0, len(cipher), 16):
        # this is the intermediate block that comes out of the decryptor
        intermediate = bytearray()
        first_block = bytearray(random_key(16))
        for target_padding_byte in range(1, 17):

            # adjust all solved bytes to match new target padding
            for solved in range(0, len(intermediate)):
                reverse_index = -(solved+1)
                first_block[reverse_index] = intermediate[reverse_index] ^ target_padding_byte

            for b in range(0, 256):
                first_block[-target_padding_byte] = b
                valid = oracle(cipher[target_start : target_start+16], first_block)
                if(valid):
                    # valid padding, b ^ found_padding = real_byte 
                    intermediate.insert(0, target_padding_byte ^ b)
                    break
                elif(b == 255):
                    raise Exception("couldn't find valid padding byte")

        cracked.extend(xortools.xor_bytes(bytes(intermediate), actual_iv))
        actual_iv = cipher[target_start : target_start + 16]
    return cracked

# this was for if the padding oracle didn't take the IV, doesn't break the first block
#def break_cbc_using_padding(oracle, cipher, iv):
#    cracked = bytearray(bytes(16))
#    target_start = 16
#    while(target_start < len(cipher)):
#        # this is the intermediate block that comes out of the decryptor
#        intermediate = bytearray()
#        first_block = bytearray(random_key(16))
#        for target_padding_byte in range(1, 17):
#
#            # adjust all solved bytes to match new target padding
#            for solved in range(0, len(intermediate)):
#                reverse_index = -(solved+1)
#                first_block[reverse_index] = intermediate[reverse_index] ^ target_padding_byte
#
#            for b in range(0, 256):
#                first_block[-target_padding_byte] = b
#                valid = oracle(cipher[0 : target_start - 16] + bytes(first_block + cipher[target_start : target_start+16]))
#                if(valid):
#                    # valid padding, b ^ found_padding = real_byte 
#                    intermediate.insert(0, target_padding_byte ^ b)
#                    break
#                elif(b == 255):
#                    raise Exception("couldn't find valid padding byte")
#
#        cracked.extend(xortools.xor_bytes(bytes(intermediate), cipher[target_start-16 : target_start]))
#        target_start += 16
#    return cracked
                
            






