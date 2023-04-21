import json
import math
import secrets
from collections import Counter
from mnemonic import Mnemonic

"""
BIP39 recovery phrase specification:
https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki

Recovery phrases are implemented in many cryptowallets, for example Mycelium:
https://wallet.mycelium.com/
"""

BITS_PER_WORD = 11


def find_entropy(customizer_phrase: str, wordlist: list, randomized_bits_count: int):
    first_letters_in_beginning = list(customizer_phrase.lower())
    wordlist_first_letter_counts = Counter(word[0] for word in wordlist)

    letter_counts_in_wordlist = [
        wordlist_first_letter_counts[b] for b in first_letters_in_beginning
    ]
    pure_entropy_count = (
        randomized_bits_count - len(first_letters_in_beginning) * BITS_PER_WORD
    )
    customized_beginning_entropy_count = sum(
        math.log2(freq) for freq in letter_counts_in_wordlist
    )
    final_entropy_count = customized_beginning_entropy_count + pure_entropy_count
    final_entropy_count = round(final_entropy_count, 2)

    ljust_width = 30
    print("Customizer phrase:".ljust(ljust_width), customizer_phrase)
    print("Original entropy:".ljust(ljust_width), randomized_bits_count)
    print("Entropy with customization:".ljust(ljust_width), final_entropy_count)


def get_bitcounts(mnemonic_word_count: int):
    mnemonic_total_bitcount = mnemonic_word_count * BITS_PER_WORD
    checksum_bitcount = mnemonic_total_bitcount // 32
    randomized_bits_count = mnemonic_total_bitcount - checksum_bitcount
    byte_count_without_checksum = randomized_bits_count // 8
    return randomized_bits_count, byte_count_without_checksum


def generate_words(customizer_phrase: str, mnemo: Mnemonic, mnemonic_word_count: int):
    wordlist = mnemo.wordlist
    first_letters_in_beginning = list(customizer_phrase.lower())
    randomized_bits_count, byte_count_without_checksum = get_bitcounts(
        mnemonic_word_count
    )

    if len(customizer_phrase) * BITS_PER_WORD >= randomized_bits_count:
        raise ValueError("Customizer phrase is too long")

    fixed_words = []
    fixed_words_indices = []
    words_by_first_letter = {
        b: [word for word in wordlist if word[0] == b]
        for b in first_letters_in_beginning
    }
    for b in first_letters_in_beginning:
        this_word = secrets.choice(words_by_first_letter[b])
        fixed_words.append(this_word)
        fixed_words_indices.append(wordlist.index(this_word))
    word_index_to_bits = lambda i: bin(i)[2:].zfill(BITS_PER_WORD)
    customized_beginning_bits = "".join(
        word_index_to_bits(i) for i in fixed_words_indices
    )

    pure_entropy_count = randomized_bits_count - len(customized_beginning_bits)
    pure_entropy = secrets.randbits(pure_entropy_count)
    pure_entropy_bitstring = bin(pure_entropy)[2:].zfill(pure_entropy_count)
    combined_data_bitstring = customized_beginning_bits + pure_entropy_bitstring
    # We put in the entropy, the library handles the checksum
    randomized_bytes = int(combined_data_bitstring, 2).to_bytes(
        byte_count_without_checksum, byteorder="big"
    )
    phrase = mnemo.to_mnemonic(randomized_bytes)
    return phrase


def main():
    mnemo = Mnemonic("english")

    wordlist = mnemo.wordlist
    word_max_length = max(len(word) for word in wordlist)

    # Set to one of [12, 15, 18, 21, 24]
    mnemonic_word_count = 12
    number_of_phrases = 10
    customizer_phrase = "fungible"
    recovery_phrases = [
        generate_words(customizer_phrase, mnemo, mnemonic_word_count)
        for _ in range(number_of_phrases)
    ]

    randomized_bits_count, _ = get_bitcounts(mnemonic_word_count)
    find_entropy(customizer_phrase, wordlist, randomized_bits_count)

    phrases_file = "phrases.json"
    with open(phrases_file, "w") as f:
        json.dump(recovery_phrases, f, indent=4)
        for recovery_phrase in recovery_phrases:
            words = recovery_phrase.split()
            # Align words
            word_room = word_max_length + 1
            formatted_phrase = "".join(f"{word.ljust(word_room)}" for word in words)
            print(formatted_phrase)


if __name__ == "__main__":
    main()
