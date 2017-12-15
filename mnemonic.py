from bitstring import BitArray
import random
import csv
from hashlib import sha256


def english_word_list(fp):
    """get the list of english mnemonic words, as defined in BIP39

    fp: the filepath to the word list, where each word is listed

    Returns: the list of 2048 mnemonic english words, as defined in BIP39"""
    words = []
    with open(fp) as csvfile:
        r = csv.reader(csvfile)
        for word in r:
            words.append(''.join(word[0]))

    return words


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


def mnemonic_words(b):
    """get the corresponding mnemonic words, as defined by BIP39
    
    b: list of bitstrings, each with length of 11 bits
    
    Returns: a list of 12 mnemonic words--a subset of the list of 2048 mnemonic words as provided in BIP39"""
    return [english_word_list('bip39words.csv')[int(b, 2)] for b in b]


def gen_mnemonic_words(verbose=False):
    if verbose:
        print('randomly generating 128 bit entropy...')
    e = gen_entropy(128)
    if verbose: 
        print('\nentropy generated:')
        print('\tx' + e.hex)

        print('\n\nadding more complexity by generating adding a checksum..')
        print('\napplying sha256 hash to the entropy to get first 4 bits as checksum:')
    cs = checksum(e)
    
    if verbose:
        print('\n\t1stfourbits( sha256(x' + e.hex + ') ) => ' + cs.bin + ' = x' + cs.hex)
        print('\nadding checksum to entropy sequence:')
    
    e_init = e.hex
    e.append(cs)
    
    if verbose:
        print('\n\tx' + e_init + ' + x' + cs.hex + ' = x' + e.hex)
        print('\ndivide this sequence into 11-bit segments...')
    
    bits = bit_split(e, 12)
    if verbose:
        for i, b in enumerate(bits):
            print('\t' + str(i+1) + '\t' + b)  

        print('\nuse the bits to lookup words from as defined in BIP39')
    
    words = mnemonic_words(bits)
    
    if verbose:
        for i, w in enumerate(words):
            print('\t' + str(i+1) + '\t' + bits[i] + '\t=>\t' + w)
    
        print('\n')
        print(words) 
    
    return words


def walkthrough():
  gen_mnemonic_words(verbose=True)  


if __name__ == '__main__':
    walkthrough()
