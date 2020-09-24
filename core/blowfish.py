from Crypto.Cipher import Blowfish
from Crypto import Random
import hashlib
import base64

class Encrypt :
    def __init__( self, key , block_size = 8 , padding = '`') :
        self.block_size = block_size
        self.padding = padding
        self.key = hashlib.md5(key.encode())

    def encrypt(self, msg):
        key = self.key.digest()
        k = lambda s : s + (self.block_size - len(s) % self.block_size) * self.padding
        iv = Random.new().read(self.block_size)
        key = self.key.digest()
        blowfishinit = Blowfish.new(key, Blowfish.MODE_CBC,iv)
        chipher = blowfishinit.encrypt(k(msg))
        return base64.b64encode(iv + chipher).decode()

    def decrypt(self, ciphertext):
        unbased = base64.b64decode(ciphertext)
        iv = unbased[:self.block_size]
        encrypted = unbased[self.block_size:]
        key = self.key.digest()
        blowfishinit = Blowfish.new(key, Blowfish.MODE_CBC,iv)
        msg = blowfishinit.decrypt(encrypted).decode()
        return msg.rstrip(self.padding)

    def getkey(self):
        return self.key.hexdigest()

