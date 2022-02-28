from hashlib import sha3_256
import sys

if len(sys.argv) != 3:
    print('Usage: hash.py value salt')
else:
    _, value, salt = sys.argv
    print(sha3_256((salt + value + salt).encode('utf-8')).hexdigest())
