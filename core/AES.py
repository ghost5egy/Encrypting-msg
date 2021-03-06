from Crypto.Cipher import AES
from Crypto import Random
import hashlib
import base64

class Encrypt :
    def __init__( self, key , block_size = 16 , padding = '`') :
        self.block_size = block_size
        self.padding = padding
        self.key = hashlib.md5(key.encode())

    def encrypt(self, msg):
        k = lambda s : s + (self.block_size - len(s) % self.block_size) * self.padding
        iv = Random.new().read(self.block_size)
        key = self.key.digest()
        aesinit = AES.new(key, AES.MODE_CBC,iv)
        ciphermsg = aesinit.encrypt(k(msg).encode()) 
        return base64.b64encode(iv + ciphermsg)

    def decrypt(self, ciphertext):
        unbased = base64.b64decode(ciphertext)
        iv = unbased[:self.block_size]
        encrypted = unbased[self.block_size:]
        key = self.key.digest()
        aesinit = AES.new(key, AES.MODE_CBC,iv)
        msg = aesinit.decrypt(encrypted)
        return msg.rstrip(self.padding)

    def getkey(self):
        return self.key.hexdigest()

