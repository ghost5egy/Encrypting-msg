import sys

msg = input("Enter message :")
key = input("Enter key : ")
alg = input("Enter Algorithm 1 for aes , 2 for ARC4 , 3 for ARC2 , 4 for blowfish, 5 for RSA: ")
if alg == '1':
    print("You choosed AES\n")
    from core.AES import Encrypt
elif alg == '2':
    print("You choosed ARC4\n")
    from core.ARC4 import Encrypt
elif alg == '3':
    print("You choosed ARC2\n")
    from core.ARC2 import Encrypt
elif alg == '4':
    print("You choosed Blowfish\n")
    from core.blowfish import Encrypt
elif alg == '5':
    print("You choosed RSA\n")
    from core.RSA import Encrypt
    a=Encrypt()
    a.generateKey()
    ciphertext = a.encrypt('public.key',msg)
    print(ciphertext)
    print(a.decrypt('privte.key',ciphertext))
    sys.exit(1)
else: 
    print("Input invalid ")

a = Encrypt(key)
print('this is the md5(key) : ',a.getkey())
chipher = a.encrypt(msg)
print('this is Encrypted message : ',chipher)
print("this is Decrypted message : ",a.decrypt(chipher))