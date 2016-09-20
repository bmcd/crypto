import aestools
from collections import OrderedDict
USERS = {}

def parse(querystring):
    output = OrderedDict()
    pairs = querystring.split('&')
    for pair in pairs:
        key, value = pair.split('=', 1)
        output[key] = value
    return output

def encode(obj):
    output = ''
    for key, value in obj.items():
        output += key
        output += '='
        output += value
        output += '&'
    # chop off last &
    return output[0:-1]

def is_admin(cookie):
    decrypted = parse_encrypted(cookie)
    return decrypted.endswith(b'role=admin')

def remove_symbols(email):
    return email.replace('&', "%26").replace('=', '%3D')

def profile(email, role):
    email = remove_symbols(email)
    return encode(create_or_get_user(email, role))

def profile_for(email, role='user'):
    encoded_profile = profile(email, role)
    return aestools.encrypt_ecb(bytes(encoded_profile, 'UTF-8'), KEY)

def parse_encrypted(bytes):
    return aestools.decrypt_ecb(bytes, KEY)

def create_or_get_user(email, role='user'):
    if email not in USERS:
        USERS[email] = User(email, role)

    return USERS[email]

KEY = aestools.random_key(16)

class User():
    nextid = 0

    def getNextId(self):
        User.nextid += 1
        return User.nextid

    def __init__(self, email, role='user'):
        self.email = email
        self.role = role
        self.id = self.getNextId()

    def items(self):
        ordereddict = OrderedDict()
        ordereddict['email'] = self.email
        ordereddict['id'] = str(self.id)
        ordereddict['role'] = self.role
        return ordereddict.items()
