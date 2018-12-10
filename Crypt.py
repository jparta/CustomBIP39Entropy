
import math
import secrets
import json
from collections import Counter
from pprint import pprint
from mnemonic import Mnemonic

"""
BIP39 recovery phrase specification:
https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

Recovery phrases are implemented in many cryptowallets, for example Mycelium:
https://wallet.mycelium.com/
"""

word_file = 'BIP39_words.json'
with open(word_file, 'r') as f:
    wordlist = json.load(f)

mnemo = Mnemonic('english')

wordlist_first_letters = [word[0] for word in wordlist]
wordlist_first_letter_counts = Counter(word[0] for word in wordlist)

# Set to one of [12, 15, 18, 21, 24]
mnemonic_word_count = 15
#
BITS_PER_WORD = 11

mnemonic_total_bitcount = mnemonic_word_count * BITS_PER_WORD
checksum_bitcount = mnemonic_total_bitcount // 32
randomized_bits_count = mnemonic_total_bitcount - checksum_bitcount
byte_count_without_checksum = randomized_bits_count // 8


def find_entropy(first_letters_in_beginning):
    letter_counts_in_wordlist = [wordlist_first_letter_counts[b] for b in first_letters_in_beginning]
    pure_entropy_count = randomized_bits_count - len(first_letters_in_beginning) * BITS_PER_WORD
    customized_beginning_entropy_count = sum(math.log2(freq) for freq in letter_counts_in_wordlist)
    final_entropy_count = customized_beginning_entropy_count + pure_entropy_count

    print("Original entropy:\t\t\t", randomized_bits_count)
    print("Entropy with customization:\t", final_entropy_count)


def generate_words(customizer_phrase):
    assert len(customizer_phrase) * BITS_PER_WORD <= randomized_bits_count, "Customizer phrase is too long"
    first_letters_in_beginning = list(customizer_phrase.lower())

    find_entropy(first_letters_in_beginning)

    fixed_words = []
    fixed_words_indices = []
    wordlist_filtered = {b: [word for word in wordlist if word[0] == b] for b in first_letters_in_beginning}
    for b in first_letters_in_beginning:
        this_word = secrets.choice(wordlist_filtered[b])
        fixed_words.append(this_word)
        fixed_words_indices.append(wordlist.index(this_word))
    customized_beginning_bits = ''.join(bin(i)[2:].zfill(BITS_PER_WORD) for i in fixed_words_indices)

    pure_entropy_count = randomized_bits_count - len(customized_beginning_bits)
    pure_entropy = secrets.randbits(pure_entropy_count)
    pure_entropy_bitstring = bin(pure_entropy)[2:].zfill(pure_entropy_count)

    combined_data_bitstring = customized_beginning_bits + pure_entropy_bitstring
    # We put in the entropy, the library handles the checksum
    randomized_bytes = int(combined_data_bitstring, 2).to_bytes(byte_count_without_checksum, byteorder='big')
    words = mnemo.to_mnemonic(randomized_bytes)

    print(words, "\n")
    return words


gen_file = "gen_file.txt"
with open(gen_file, 'w') as f:
    n = 10
    customizer_phrase = "julmetunvehje"
    recovery_phrase = [generate_words(customizer_phrase) for _ in range(n)]
    pprint(recovery_phrase, stream=f, width=256)