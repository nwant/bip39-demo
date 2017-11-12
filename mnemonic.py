from bitstring import BitArray
import random
from hashlib import sha256
from bip39 import english_word_list


def gen_entropy(n):
    """generate a random entropy bitarray

    n: the length of the entropy

    Returns: the entropy bit array"""
    s = random.randint(0, 2**n - 1)
    return BitArray(uint=s, length=n)


def checksum(e):
    """generate a checksum from a entropy bitarray by using the first four bits of its sha256 hash

    e: an entropy bit array

    Returns: the 4 bit size bit array the corresponds to the checksum of the provided entropy bit array"""
    sha256hash = BitArray(sha256(e.bytes).digest())
    return sha256hash[:4]


def bit_split(b, s):
    """split a bit array into 12 equal parts

    b: the bit array to split
    s: the number of bits each section of the split should be

    Returns: a list of bits, where each bit is a binary string"""
    bits = []
    size = int(len(b)/s)
    for i in range(0, s):
        start = i * size
        end = start + size
        bits.append(b[start:end].bin)

    return bits


def gen_mnemonic_words():
    """generate a new set of 12 mnemonic words, as defined by BIP39

    Returns: a list of 12 mnemonic words--a subset of the list of 2048 mnemonic words as provided in BIP39"""
    e = gen_entropy(128)
    # add the checksum to the end of the random sequence
    e.append(checksum(e))
    # split into 12 segments of 11 bits each
    bit_segments = bit_split(e, 12)
    # use these segments to look up the corresponding words, as defined in BIP39
    return [english_word_list()[int(b, 2)] for b in bit_segments]


if __name__ == '__main__':
    print(gen_mnemonic_words())
