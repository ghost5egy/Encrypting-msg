from Crypto.Cipher import ARC2
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
        arc2init = ARC2.new(key, ARC2.MODE_CBC,iv)
        chipher = arc2init.encrypt(k(msg))
        return base64.b64encode(iv + chipher)

    def decrypt(self, ciphertext):
        unbased = base64.b64decode(ciphertext)
        iv = unbased[:self.block_size]
        encrypted = unbased[self.block_size:]
        key = self.key.digest()
        arc2init = ARC2.new(key, ARC2.MODE_CBC,iv)
        msg = arc2init.decrypt(encrypted)
        return msg.rstrip(self.padding)

    def getkey(self):
        return self.key.hexdigest()

