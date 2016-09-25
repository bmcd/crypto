import frequency
import conv
from distance import Distance

def xor_bytes(bytes_one, bytes_two):
    output_bytes = bytearray()
    for i in range(0, len(bytes_one)):
        output_bytes.append(bytes_one[i] ^ bytes_two[i])
    return bytes(output_bytes)

def xor_against_byte(bytes_array, xor_byte):
    output_bytes = bytearray()
    for i in range(0, len(bytes_array)):
        output_bytes.append(bytes_array[i] ^ xor_byte)
    return bytes(output_bytes)

def solve_xor_block(encoded_bytes):
    current_score = 0
    current_byte = None
    current_bytes = None
    for b in range(0, 256):
        test_byte = bytes([b])[0]
        decoded_bytes = xor_against_byte(encoded_bytes, test_byte)
        score = frequency.scoreof(decoded_bytes)
        if current_score == 0 or score < current_score:
            current_score = score 
            current_byte = test_byte
            current_bytes = decoded_bytes
    return (current_byte, current_bytes, current_score)

def find_xored_bytes(file):
    current_score = 0
    current_encrypted = bytes()
    current_decrypted = bytes()
    for line in file:
        input = conv.hex_to_bytes(line.rstrip())
        (b, output, score) = solve_xor_block(input)
        if current_score == 0 or score < current_score:
            current_score = score 
            current_encrypted = input
            current_decrypted = output
    return (current_encrypted, current_decrypted)

def xor_repeating(input_bytes, key_bytes):
    output_bytes = bytearray()
    for i in range(0, len(input_bytes)):
        output_bytes.append(input_bytes[i] ^ key_bytes[i % len(key_bytes)])
    return output_bytes

def distance(bytesone, bytestwo):
    distance = 0
    for i in range(0, len(bytesone)):
        xored_byte = bytesone[i] ^ bytestwo[i]
        distance += _countsetbits(xored_byte)
    return distance

def _countsetbits(b):
    return bin(b).count("1")

def breakxor(raw, keysize=-1):
    if(keysize == -1):
        distances = get_probable_key_sizes(raw)
    else:
        diff = get_normalized_distance(raw, keysize, 4)
        distances = [Distance(keysize, diff)]
    best_decrypted = None
    best_score = None
    for dist in distances:
        keysize = dist.keysize

        blocks = [[] for _ in range(keysize)]
        for i in range(0, len(raw)):
            pos = i % keysize
            blocks[pos].append(raw[i])

        key = bytearray()
        for block in blocks:
            b, output, score = solve_xor_block(block)
            key.append(b)
        
        decrypted = xor_repeating(raw, key)
        score = frequency.scoreof(decrypted)
        if( best_score is None or score < best_score):
            best_decrypted = (key, decrypted)
            best_score = score

    return best_decrypted
    

def get_probable_key_sizes(raw):
    distances = []
    for keysize in range(2, 40):
        iterations = 4
        #print(normalized_diff)
        normalized_diff = get_normalized_distance(raw, keysize, iterations)
        distances.append(Distance(keysize, normalized_diff))
    return sorted(distances)[0:3]

def get_normalized_distance(raw, blocksize=16, iterations=4):
        total_blocks = len(raw) // blocksize
        iterations = total_blocks if total_blocks < iterations else iterations
        total = 0
        for x in range(iterations):
            start = x * blocksize
            mid = (x + 1) * blocksize
            end = (x + 2) * blocksize
            b1 = raw[start:mid]
            b2 = raw[mid:end]
            total += distance(b1, b2)

        return total / iterations / blocksize
