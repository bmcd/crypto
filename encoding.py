

def parse(querystring):
    output = {}
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
    return output[0:-2]

def profile_for(email):
    email = email.replace('&', "%26").replace('=', '%3D')
    return encode(User(email))

KEY = aestools.random_key(16)

def encrypted_profile(email):
    user = profile_for(email)
    return aestools.encrypt_ecb(user, KEY)

def decrypt_profile(encrypted):
    decrypted = aestools.decrypt_ecb(encrypted, KEY)
    return parse(decrypted)

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
        return { 'email': self.email, 'role': self.role, 'id': str(self.id) }.items()
