import base64
import binascii

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

def xorStrings(stringOne, stringTwo):
    xored_bytes = xorBytes(hexToBytes(stringOne), hexToBytes(stringTwo))
    return bytesToHexString(xored_bytes)

print("Answer 1: " + hexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
print("Answer 2: " + xorStrings("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"))
