import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import time
import argparse
from random import randint
from utils_demo import *

# Reads cipher text value into bytearray variable
c_c = read_bytes("Exhaustive Search Project/c_c.bin")
# Reads nonce value into bytearray variable
nonce_c = read_bytes("Exhaustive Search Project/nonce_c.bin")
# Reads key values into bytearray variable
key = read_bytes("Exhaustive Search Project/key.bin")

# Decrypt function defined in utils_demo.py
print(str(decryptor_CTR(c_c, nonce_c, key), 'UTF-8'))

