from bitstring import BitArray
from mnemonic import gen_mnemonic_words
from hashlib import pbkdf2_hmac


def gen_seed(m, p=None):
    """generate a 512 bit seed using a list of 12 mnemonic words,
    as defined in BIP39 using an optional passphrase"""
    pwd = ' '.join(m)
    salt = 'mnemonic' if p is None else 'mnemonic' + p
    dk = pbkdf2_hmac('sha512', pwd.encode(), salt.encode(), 2048)
    return BitArray(dk)


if __name__ == '__main__':
    print(len(gen_seed(gen_mnemonic_words()).bin))
