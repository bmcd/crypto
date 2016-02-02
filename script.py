import base64

def hexToBase64(hexString):
    decoded_bytes = bytes.fromhex(hexString)
    return base64.b64encode(decoded_bytes).decode("ascii")

print(hexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
