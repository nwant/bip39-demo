import hmac
from hashlib import sha512
from bitstring import BitArray
from secp256k1 import PrivateKey, PublicKey


def gen_masters(s):
    """generate the master secret key and the master chaincode from a master seed

    s: the master seed

    Return: a tuple with the master secret key as the first value and the master
    master chaincode the second value"""
    h = hmac.new(s, None, sha512)
    b = BitArray(h)
    return b[:256], b[257:]


