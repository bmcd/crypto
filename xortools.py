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
        count = 0
        counts = {}
        for char_byte in decoded_bytes:
            char = chr(char_byte)
            counts.setdefault(char, 0)
            counts[char] += 1
            count += 1
        score = score_counts(counts, count)
        if current_score == 0 or score < current_score:
            current_score = score 
            current_byte = test_byte
            current_bytes = decoded_bytes
    return (current_byte, current_bytes, current_score)

# TODO put this in frequency.py
def score_counts(counts, count):
    score = 0.0
    for char in frequency.dict:
        letter_count = counts.get(char, 0)
        difference = abs((letter_count / count) - frequency.dict.get(char, 0.0))
        score += difference
    return score

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

def breakxor(raw):
    distances = get_probable_key_sizes(raw)
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
        return (key, decrypted)

def get_probable_key_sizes(raw):
    distances = []
    for keysize in range(2, 40):
        # TODO why so many iterations necessary?
        iterations = 16
        total = 0
        for x in range(iterations):
            start = x * keysize
            mid = (x + 1) * keysize
            end = (x + 2) * keysize
            b1 = raw[start:mid]
            b2 = raw[mid:end]
            total += distance(b1, b2)

        normalized_diff = total / iterations / keysize
        #print(normalized_diff)
        distances.append(Distance(keysize, normalized_diff))
    return sorted(distances)[0:1]

