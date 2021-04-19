import sys
import ssl
import hashlib
import binascii

randomBytes = ssl.RAND_bytes

def generatePrivateKey(length):
    bytes = length // 8 + 8
    rand = randomBytes(bytes)
    return rand

def generatePublicKey(privateKey, prime, generator):
    publicKey = pow(generator, int.from_bytes(privateKey, "big"), prime) #g^a mod prime
    return publicKey

def generateSecret(publicKey, privateKey, prime):
    sharedSecret = pow(int.from_bytes(publicKey, "big"), int.from_bytes(privateKey, "big"), prime) #then this creates (g^a)^b
    sharedSecretBytes = sharedSecret.to_bytes(((sharedSecret.bit_length()  + 7) // 8), byteorder='big')
    hashFunc = hashlib.sha256()
    hashFunc.update(bytes(sharedSecretBytes))
    key = hashFunc.hexdigest()
    return binascii.unhexlify(key)