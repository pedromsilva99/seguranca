import sys
import random

from ciphers import encrypt_aes_pycrypto, decrypt_aes_pycrypto

ls = ['a', 'b', 'c',  'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',]

def randN():
    s=""
    for i in range(0,16):
        r = random.randint(0,25)
        s = s + ls[r]
    return s


pseu = ["0", "1", "2", "3", "4", "5"]
aux = ["0", "1", "2", "3", "4", "5"]
dct_pseu_key = {}
dct_newpsew_cipher = {}

for l in pseu:
    dct_pseu_key[l] = randN()

random.shuffle(aux)

for i in pseu:
    dct_newpsew_cipher[aux.pop()] =  encrypt_aes_pycrypto(i,dct_pseu_key[i])

print(dct_pseu_key)

print("------------------")

print(dct_newpsew_cipher)
def decodeable(data):
    try:
        data = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True
for i in dct_pseu_key:
    decipher = decrypt_aes_pycrypto(dct_pseu_key[i], dct_newpsew_cipher['0'])
    if decodeable(decipher):
        print(decipher.decode("utf-8").strip())

# s=randN()
# temp = encrypt_aes_pycrypto("nao me", s)
# print(temp)
# print(decrypt_aes_pycrypto(s,temp))