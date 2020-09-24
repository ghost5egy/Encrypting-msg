from Crypto.Cipher import ARC4
from Crypto import Random
import hashlib
import base64

class Encrypt :
    def __init__( self, key , block_size = 1) :
        self.key = hashlib.md5(key.encode())
        self.block_size = block_size

    def encrypt(self, msg):
        key = self.key.digest()
        iv = Random.new().read(16)
        tempkey = hashlib.md5(iv + key).digest()
        arc4init = ARC4.new(tempkey)
        cipertext = arc4init.encrypt(msg.encode())
        return base64.b64encode(iv + cipertext)

    def decrypt(self, ciphertext):
        key = self.key.digest()
        unbased = base64.b64decode(ciphertext)
        iv = unbased[:16]
        encrypted = unbased[16:]
        tempkey = hashlib.md5(iv + key).digest()
        arc4init = ARC4.new(tempkey)
        msg = arc4init.decrypt(encrypted)
        return msg

    def getkey(self):
        return self.key.hexdigest()

