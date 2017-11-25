from mnemonic import gen_mnemonic_words


if __name__ == '__main__':
    print('randomly selecting mneomnic words from BIP 39:')
    [print(str(i+1) + ': ' + word) for i, word in enumerate(gen_mnemonic_words())]
