import binascii
import base64

def hex_to_bytes(hexString):
    return bytes.fromhex(hexString)

def bytes_to_hex(input_bytes):
    return binascii.hexlify(input_bytes).decode("ascii")

def bytes_to_base_64(raw_bytes):
    return base64.b64encode(raw_bytes).decode("ascii")

def base_64_to_bytes(base64_string):
    return base64.b64decode(base64_string)

def hex_to_base_64(hexString):
    decoded_bytes = hex_to_bytes(hexString)
    return bytes_to_base_64(decoded_bytes)

