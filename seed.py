from bitstring import BitArray
from mnemonic import gen_mnemonic_words
from hashlib import pbkdf2_hmac
from secp256k1 import *

def gen_seed(m, p=None):
    """generate a 512 bit seed using a list of 12 mnemonic words, as defined in BIP39 using an optional passphrase

    m: list of 12 mnemonic words, which would be a subset of the 2048 mnemonic words listed in bip39
    p: optional passphrase for the seed

    Returns: a bit array of the generated seed
    """
    pwd = ' '.join(m)
    salt = 'mnemonic' if p is None else 'mnemonic' + p
    rounds = 2048
    seed = pbkdf2_hmac('sha512', pwd.encode(), salt.encode(), rounds)
    return BitArray(seed)



if __name__ == '__main__':
    print(len(gen_seed(gen_mnemonic_words()).bin))
