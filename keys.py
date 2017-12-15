import hmac
from Crypto.Hash import RIPEMD
from hashlib import sha256, sha512
from bitstring import BitArray
from secp256k1 import PrivateKey, PublicKey
from base58 import b58encode
import sys


def gen_masters(s):
    """generate the master secret key and the master chaincode from a master seed

    s: the master seed

    Return: a tuple with the master secret key as the first value and the master
    master chaincode the second value"""
    h = hmac.new(s, None, sha512)
    b = BitArray(h.digest())
    return b[:256], b[257:]


def gen_public_key(priv):
    privkey = PrivateKey(bytes(bytearray.fromhex(priv)))
    return privkey.pubkey.serialize()
    

def btc_address(pub):
    """generate a bitcoin address from a public key
    
    pub: a public key to generate the bitcoin address with
    
    Return: the bitcoin address derived from the public key"""
    h = RIPEMD.new(data=pub)
    prefix = '00'
    hexstr = prefix + h.hexdigest()
    return b58encode(bytes(bytearray.fromhex(hexstr)))


if __name__ == '__main__':
    words = sys.argv[0]
    
