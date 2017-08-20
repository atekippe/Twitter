import string
import random
import base64
import binascii
from random import randint
from Crypto.Hash import *
from Crypto.Cipher import *
from Crypto import Random
import itertools
from itertools import chain, product

def random_string(length, characters=string.ascii_uppercase + string.ascii_lowercase + string.digits):
    return ''.join(random.choice(characters) for _ in range(length))


def Hash_HMAC(string):
    secret = random_string(5)
    print(secret)
    h = HMAC.new(b'secret')
    h.update(string)
    return [h.hexdigest(), ""]

data = 'test1'
print(Hash_HMAC(data.encode("utf-8")))

#res = itertools.permutations('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', 5)
#print(res)
"""
for i in res:
    print(''.join(i))
"""
