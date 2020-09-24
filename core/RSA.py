from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto import Random
from Crypto.Hash import SHA
import base64

class Encrypt:
    def __init__(self):
        self.privkey = ''
        self.publkey = ''

    def generateKey(self):
        key = RSA.generate(2048)
        self.privkey = key.exportKey()
        with open('privte.key' , 'w') as f:
            f.write(self.privkey.decode())
        self.publkey = key.publickey().exportKey()
        with open('public.key' , 'w') as f:
            f.write(self.publkey.decode())

    def getpublkey(self):
        return self.publkey
    
    def getprivkey(self):
        return self.privkey
    
    def encrypt(self, key, msg):
        keypub = RSA.importKey(open(key).read())
        rsainit = PKCS1_v1_5.new(keypub)
        encmsg = rsainit.encrypt(msg.encode())
        return base64.b64encode(encmsg)

    def decrypt(self, key, ciphertext):
        keyprv = RSA.importKey(open(key).read())
        rsainit = PKCS1_v1_5.new(keyprv)
        return rsainit.decrypt(base64.b64decode(ciphertext),Random.new().read(15 % SHA.digest_size)).decode()
