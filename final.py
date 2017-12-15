from bitarray import bitarray
from mnemonic import *
from seed import *
from keys import *


if __name__ == '__main__':
    words = gen_mnemonic_words()
    s = gen_seed(words) 
    mk = gen_masters(bitarray(s.bin).tobytes())
    k = mk[0]
    print(k)
    K = gen_public_key(k.hex)
    print(K)        
    addr = btc_address(K)
    print(addr)
