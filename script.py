import os
import base64
import binascii
import frequency

def hexToBytes(hexString):
    return bytes.fromhex(hexString)

def bytesToHexString(input_bytes):
    return binascii.hexlify(input_bytes).decode("ascii")

def bytesToBase64String(raw_bytes):
    return base64.b64encode(raw_bytes).decode("ascii")

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
    current_score = 0
    current_string = ""
    for b in range(0, 256):
        decoded_bytes = xorAgainstByte(encoded_bytes, bytes([b])[0])
        count = 0
        counts = {}
        for charByte in decoded_bytes:
            character = chr(charByte)
            counts.setdefault(character, 0)
            counts[character] += 1
            count += 1
        score = scoreCounts(counts, count)
        if current_score == 0 or score < current_score:
            current_score = score 
            current_string = decoded_bytes.decode("utf-8", errors='replace')
    return (current_string, current_score)

def scoreCounts(counts, count):
    score = 0.0
    for char in frequency.dict:
        letter_count = counts.get(char, 0)
        difference = abs((letter_count / count) - frequency.dict[char])
        score += difference
    return score

def findXoredString():
    current_score = 0
    current_string = ""
    file = open("4.txt", "r")
    for line in file:
        line = line.rstrip()
        try:
            (string, score) = findlegit(line)
        except:
            print("bad input " + line)
            continue
        if current_score == 0 or score < current_score:
            current_score = score 
            current_string = string
    return current_string

def repeatingXor(file, key):
    input_bytes = bytearray(file.read().rstrip(), "utf-8")
    key_bytes = bytearray(key, "utf-8")
    output_bytes = bytearray()
    for i in range(0, len(input_bytes)):
        output_bytes.append(input_bytes[i] ^ key_bytes[i % len(key_bytes)])
    return bytesToHexString(output_bytes)

print("Answer 1: " + hexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
print("Answer 2: " + xorStrings("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"))
print("Answer 3: " + findlegit("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")[0])
# print("Answer 4: " + findXoredString())
print("Answer 5: " + repeatingXor(open("5.txt", "r"), "ICE"))


test1 = "this is a test"
test2 = "wokka wokka!!!"

def hamming(stringone, stringtwo):
    distance = 0
    bytesone = bytes(stringone, "utf-8")
    bytestwo = bytes(stringtwo, "utf-8")
    for i in range(0, len(bytesone)):
        if bytesone[i] != bytestwo[i]:
            distance += 1
    print(distance)

hamming(test1, test2)
