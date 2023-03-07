# University of North Texas, College of Engineering
# Class: CSCE 4050/5050 Applications of Cryptography
# Instructor: Dr. Kirill Morozov
# Authors: Alex Zuehlke (AlexanderZuehlke@my.unt.edu) and Cesar Romo ()
# Date: 3/6/2023
# Description: The primary function of this program is to determine the last 24 bits of a 128-bit AES encryption key. Known plaintexts, nonces, and ciphertexts are necessary for proper operation.

# Headers
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import time
import argparse
from random import randint
from utils_demo import *

# Modified encryption function. It gets a plaintext a key and returns the ciphertext and nonce.
def encryptor(message, key, nonce):
    cipher = AES.new(key, AES.MODE_CTR)
    ct = cipher.encrypt(message)  
    nonce = cipher.nonce
    return ct

m1 = read_file("Exhaustive Search Project/m1.txt")
m1 = bytes(m1, 'utf-8') # Converts from UTF-8 to byte type usable by AES encryption function
m2 = read_file("Exhaustive Search Project/m2.txt")
m2 = bytes(m2, 'utf-8') # Converts from UTF-8 to byte type usable by AES encryption function
m3 = read_file("Exhaustive Search Project/m3.txt")
m3 = bytes(m3, 'utf-8') # Converts from UTF-8 to byte type usable by AES encryption function

# Reads nonce values into bytearray variables
nonce_c = read_bytes("Exhaustive Search Project/nonce_c.bin")
nonce1 = read_bytes("Exhaustive Search Project/nonce1.bin")
nonce2 = read_bytes("Exhaustive Search Project/nonce2.bin")
nonce3 = read_bytes("Exhaustive Search Project/nonce3.bin")

# Reads ciphertext values into bytearrar variables 
c_c = read_bytes("Exhaustive Search Project/c_c.bin")
c1 = read_bytes("Exhaustive Search Project/c1.bin")
c2 = read_bytes("Exhaustive Search Project/c2.bin")
c3 = read_bytes("Exhaustive Search Project/c3.bin")


for key in range(2 ** 24):
    
    pretex_key = 2 ** 127
    full_key = pretex_key + key
    full_key = format(full_key, "b")
    full_key = bitstring_to_bytes(full_key)
    print(full_key)

    if encryptor(m1, full_key, nonce1) == c1:
        if encryptor(m2, full_key, nonce2) == c2 & encryptor(m3, full_key, nonce3) == c3:
            break

print(full_key)
