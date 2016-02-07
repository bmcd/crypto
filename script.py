import os
import base64
import binascii
import frequency
from Crypto.Cipher import AES

def hexToBytes(hexString):
    return bytes.fromhex(hexString)

def bytesToHexString(input_bytes):
    return binascii.hexlify(input_bytes).decode("ascii")

def bytesToBase64String(raw_bytes):
    return base64.b64encode(raw_bytes).decode("ascii")

def base64ToBytes(base64_string):
    return base64.b64decode(base64_string)

def hexToBase64(hexString):
    decoded_bytes = hexToBytes(hexString)
    return bytesToBase64String(decoded_bytes)

def xorBytes(bytesOne, bytesTwo):
    outputBytes = bytearray()
    for i in range(0, len(bytesOne)):
        outputBytes.append(bytesOne[i] ^ bytesTwo[i])
    return bytes(outputBytes)

def xorAgainstByte(bytesArray, xorByte):
    outputBytes = bytearray()
    for i in range(0, len(bytesArray)):
        outputBytes.append(bytesArray[i] ^ xorByte)
    return bytes(outputBytes)

def xorStrings(stringOne, stringTwo):
    xored_bytes = xorBytes(hexToBytes(stringOne), hexToBytes(stringTwo))
    return bytesToHexString(xored_bytes)

def findlegit(hexString):
    encoded_bytes = hexToBytes(hexString)
    return findBestByte(encoded_bytes)

def findBestByte(encoded_bytes):
    current_score = 0
    current_byte = None
    current_bytes = None
    for b in range(0, 256):
        test_byte = bytes([b])[0]
        decoded_bytes = xorAgainstByte(encoded_bytes, test_byte)
        count = 0
        counts = {}
        for charByte in decoded_bytes:
            char = chr(charByte)
            counts.setdefault(char, 0)
            counts[char] += 1
            count += 1
        score = scoreCounts(counts, count)
        if current_score == 0 or score < current_score:
            current_score = score 
            current_byte = test_byte
            current_bytes = decoded_bytes
    return (current_bytes, current_score, current_byte)

def scoreCounts(counts, count):
    score = 0.0
    for char in frequency.dict:
        letter_count = counts.get(char, 0)
        difference = abs((letter_count / count) - frequency.dict.get(char, 0.0))
        score += difference
    return score

def findXoredString():
    current_score = 0
    current_string = ""
    file = open("4.txt", "r")
    for line in file:
        line = line.rstrip()
        try:
            (current_bytes, score, b) = findlegit(line)
        except:
            print("bad input " + line)
            continue
        if current_score == 0 or score < current_score:
            current_score = score 
            current_string = current_bytes.decode("utf-8", errors='replace')
    return current_string

def repeating(file, key):
    input_bytes = bytearray(file.read().rstrip(), "utf-8")
    key_bytes = bytearray(key, "utf-8")
    return bytesToHexString(repeatingXor(input_bytes, key_bytes))

def repeatingXor(input_bytes, key_bytes):
    output_bytes = bytearray()
    for i in range(0, len(input_bytes)):
        output_bytes.append(input_bytes[i] ^ key_bytes[i % len(key_bytes)])
    return output_bytes

print("Answer 1: " + hexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
print("Answer 2: " + xorStrings("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"))
print("Answer 3: " + findlegit("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")[0].decode("utf-8", errors='replace'))
# print("Answer 4: " + findXoredString())
print("Answer 5: " + repeating(open("5.txt", "r"), "ICE"))


test1 = "this is a test"
test2 = "wokka wokka!!!"

def distanceStrings(stringone, stringtwo):
    bytesone = bytes(stringone, "utf-8")
    bytestwo = bytes(stringtwo, "utf-8")
    return distance(bytesone, bytestwo)

def distance(bytesone, bytestwo):
    distance = 0
    for i in range(0, len(bytesone)):
        xored_byte = bytesone[i] ^ bytestwo[i]
        distance += countsetbits(xored_byte)
    return distance

def countsetbits(b):
    return bin(b).count("1")

class Distance(object):
    def __init__(self, keysize, distance):
        self.keysize = keysize
        self.distance = distance

    def __repr__(self):
        return "{}: {}".format(self.keysize, self.distance)

    def __lt__(self, other):
        return self.distance < other.distance


def breakxor(file):
    raw = base64ToBytes(file.read())
    distances = getProbableKeySizes(raw)
    for dist in distances:
        keysize = dist.keysize

        blocks = [[] for _ in range(keysize)]
        for i in range(0, len(raw)):
            pos = i % keysize
            blocks[pos].append(raw[i])

        key = bytearray()
        for block in blocks:
            (string, score, b) = findBestByte(block)
            key.append(b)
        
        print(repeatingXor(raw, key).decode("utf-8", errors="replace"))
        print(key)





def getProbableKeySizes(raw):
    distances = []
    for keysize in range(2, 40):
        iterations = 4
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
    return sorted(distances)[0:3]

#breakxor(open("6.txt", "r"))

def challenge7():
    input = base64ToBytes(open("7.txt", "r").read())
    print(decryptCbc(input, "YELLOW SUBMARINE").decode("utf-8"))

def decryptEcb(input, key):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.decrypt(input)

def encryptEcb(input, key):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(input)

#challenge7()

def findAes():
    file = open("8.txt", "r")
    for line in file:
        line = line.rstrip()
        raw = hexToBytes(line)
        blocksize = 16
        tests = {}
        for i in range(0, len(raw) // blocksize):
            subblock = raw[i * blocksize:(i + 1) * blocksize]
            string = bytesToHexString(subblock)
            if string in tests:
                return line
            tests[string] = True
            
    return "No repeating blocks in any ciphertexts"



#print(findAes())

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


def encryptCbc(input, key, iv):
    blocksize = 16
    last = iv
    output = bytearray()
    blocks = chunks(input, blocksize)
    for block in blocks:
        if len(block) < blocksize:
            block = padded(block, blocksize)
        combined = xorBytes(last, block)
        encrypted = encryptEcb(combined, key)
        output.extend(encrypted)
        last = encrypted
    return output

def decryptCbc(input, key, iv):
    blocksize = 16
    last = iv
    output = bytearray()
    blocks = chunks(input, blocksize)
    for block in blocks:
        decrypted = decryptEcb(bytes(block), key)
        combined = xorBytes(last, decrypted)
        output.extend(combined)
        last = block
    return strippadding(output)

#print(decryptCbc(encryptCbc(bytes("this is a test!!1234567890123456xxx", "utf-8"), bytes("YELLOW SUBMARINE", "utf-8"), bytes("0000000000000000", "utf-8")), bytes("YELLOW SUBMARINE", "utf-8"), bytes("0000000000000000", "utf-8")))

def challenge10():
    file = open('10.txt', 'r')
    input = base64ToBytes(file.read().rstrip())
    return decryptCbc(input, bytes("YELLOW SUBMARINE", "ascii"), b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

print(challenge10().decode('utf-8'))
