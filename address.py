from hashlib import sha256
from Crypto.Hash import RIPEMPD

btc_address(pk):
    """generate a bitcoin address from a public key
    
    pk: a public key to generate the bitcoin address with
    
    Return: the bitcoin address derived from the public key"""
    h = RIPEMD.new()
    h.update(sha256(pk))
    return h.hexdigest()


if __name__ == '__main__':
    
