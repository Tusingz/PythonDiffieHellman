import socket
import sys
import ssl
import hashlib
from encryption import *

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#4096 prime taken from https://tools.ietf.org/html/rfc3526
#This prime is: 2^4096 - 2^4032 - 1 + 2^64 * { [2^3966 pi] + 240904 }
prime16 = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF
generator = 2
# Connect the socket to the port where the server is listening
server_address = ('localhost', 10000)
print('connecting to %s port %s' %server_address)
sock.connect(server_address)

try:   
    private = generatePrivateKey(1024) #change this idk if this number is right
    public = generatePublicKey(private, prime16, generator)
    print("Sending public key")
    sock.sendall(public.to_bytes(((public.bit_length() + 7) // 8), byteorder="big"))
    # Look for the response
    amount_received = 0
    amount_expected = (public.bit_length() + 7) // 8

    while amount_received < amount_expected:
        data = sock.recv(((public.bit_length() + 7) // 8))
        amount_received += len(data)
        print("Received servers public key")

    secret = generateSecret(data, private, prime16) #then this creates (g^a)^b
    print(secret)

finally:
    print("Closing Socket")
    sock.close()