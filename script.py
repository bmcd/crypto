import base64
import binascii

frequencies = {};
frequencies['a'] = 0.08167
frequencies['b'] = 0.01492
frequencies['c'] = 0.02782
frequencies['d'] = 0.04253
frequencies['e'] = 0.12702
frequencies['f'] = 0.02228
frequencies['g'] = 0.02015
frequencies['h'] = 0.06094
frequencies['i'] = 0.06966
frequencies['j'] = 0.00153
frequencies['k'] = 0.00772
frequencies['l'] = 0.04025
frequencies['m'] = 0.02406
frequencies['n'] = 0.06749
frequencies['o'] = 0.07507
frequencies['p'] = 0.01929
frequencies['q'] = 0.00095
frequencies['r'] = 0.05987
frequencies['s'] = 0.06327
frequencies['t'] = 0.09056
frequencies['u'] = 0.02758
frequencies['v'] = 0.00978
frequencies['w'] = 0.02360
frequencies['x'] = 0.00150
frequencies['y'] = 0.01974
frequencies['z'] = 0.00074

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
    for b in range(0, 256):
        print(b)
        print(bytes([b])[0])
        decoded_bytes = xorAgainstByte(encoded_bytes, bytes([b])[0])
        decoded_string = decoded_bytes.decode("utf-8")
        print(decoded_string)
        count = 0
        counts = {}
        for character in decoded_string:
            counts.setdefault(character, 0)
            counts[character] += 1
            count += 1
        # scoreCounts(counts)

print("Answer 1: " + hexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
print("Answer 2: " + xorStrings("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"))
findlegit("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
