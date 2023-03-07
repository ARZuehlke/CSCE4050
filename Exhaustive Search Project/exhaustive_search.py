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

# This is a modified encryption function for the AES loop, it uses the messages and nonces provided
def mod_encryptor_CTR(message, key, nonce):
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
    ct = cipher.encrypt(message)    
    return ct

m1 = read_file("Exhaustive Search Project/m1.txt")
m1 = string_to_bytes(m1) # Converts from UTF-8 to bytearray usable by AES encryption function
m2 = read_file("Exhaustive Search Project/m2.txt")
m2 = string_to_bytes(m2) # Converts from UTF-8 to bytearray usable by AES encryption function
m3 = read_file("Exhaustive Search Project/m3.txt")
m3 = string_to_bytes(m3) # Converts from UTF-8 to bytearray usable by AES encryption function

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

# For loop to iterate through a 24 bit keyspace 
for key in range(2 ** 24):
    
    pretext_key = 2 ** 127
    full_key = pretext_key + key # Increment key +1
    full_key = format(full_key, "b") # Convert key to bitstring
    full_key = bitstring_to_bytes(full_key) # Convert bitstring to bytearray usable by mod_encryptor_CTR
    
    if mod_encryptor_CTR(m1, full_key, nonce1) == c1:
        if (mod_encryptor_CTR(m2, full_key, nonce2) == c2) & (mod_encryptor_CTR(m3, full_key, nonce3) == c3):
            break

# Store the full_key from the loop into new variable found_key
found_key = full_key
# Print the found key to the terminal
print(found_key)
# Open key.bin file and write found_key as bytearray
write_bytes("Exhaustive Search Project/key.bin", found_key)


# actual_key = b'\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00_\xeed'




