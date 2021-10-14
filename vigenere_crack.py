# From https://www.coursera.org/learn/cryptography
# Problem statement: You know that this cyphertext was generated using a key with
# a length in the range 1 --> 14. Encryption has been done by XOR'ing the plaintext
# with the key.

import string
# load english frequencies
english_freq = {}
english_deviation = 0
with open('./ascii_freq.txt', 'r') as f:
    for line in f:
        data = line.strip().split(':')
        english_freq[int(data[0])] = float(data[1])
        english_deviation += float(data[1]) ** 2


# convert ciphertext to actual hex
in_str = 'F96DE8C227A259C87EE1DA2AED57C93FE5DA36ED4EC87EF2C63AAE5B9A7EFFD673BE4ACF7BE8923CAB1ECE7AF2DA3DA44FCF7AE29235A24C963FF0DF3CA3599A70E5DA36BF1ECE77F8DC34BE129A6CF4D126BF5B9A7CFEDF3EB850D37CF0C63AA2509A76FF9227A55B9A6FE3D720A850D97AB1DD35ED5FCE6BF0D138A84CC931B1F121B44ECE70F6C032BD56C33FF9D320ED5CDF7AFF9226BE5BDE3FF7DD21ED56CF71F5C036A94D963FF8D473A351CE3FE5DA3CB84DDB71F5C17FED51DC3FE8D732BF4D963FF3C727ED4AC87EF5DB27A451D47EFD9230BF47CA6BFEC12ABE4ADF72E29224A84CDF3FF5D720A459D47AF59232A35A9A7AE7D33FB85FCE7AF5923AA31EDB3FF7D33ABF52C33FF0D673A551D93FFCD33DA35BC831B1F43CBF1EDF67F0DF23A15B963FE5DA36ED68D378F4DC36BF5B9A7AFFD121B44ECE76FEDC73BE5DD27AFCD773BA5FC93FE5DA3CB859D26BB1C63CED5CDF3FE2D730B84CDF3FF7DD21ED5ADF7CF0D636BE1EDB79E5D721ED57CE3FE6D320ED57D469F4DC27A85A963FF3C727ED49DF3FFFDD24ED55D470E69E73AC50DE3FE5DA3ABE1EDF67F4C030A44DDF3FF5D73EA250C96BE3D327A84D963FE5DA32B91ED36BB1D132A31ED87AB1D021A255DF71B1C436BF479A7AF0C13AA14794'
ciphertext = bytes.fromhex(in_str)


# find length of key
deviation = {}
for l in range(1, 14):
    # verify that this key length gives a distribution that has a similar shape to
    # the english frequency destribution
    cipher_freq = {} # the frequency of characters appearing in this stream of the ciphertext
    stream_len = 0
    for i in range(0, len(ciphertext), l):
        cipher_freq[ciphertext[i]] = cipher_freq.get(ciphertext[i], 0) + 1
        stream_len += 1
    for c in range (256):
        deviation[l] = deviation.get(l, 0) + (cipher_freq.get(c, 0)/stream_len)**2
# it's tedious to check precise numbers, so just take the length that gives
# the largest deviation from the uniform distribution
# I have kept the deviation dict (and didn't get the running max) just
# in case I need to checkout other key lengths
key_legth = 0
max_dev = 0
for length, dev in deviation.items():
    if dev > max_dev:
        key_legth = length
        max_dev = dev


# find out the key
keys = [{} for i in range(key_legth)]
for l in range(key_legth):
    # find the byte that makes all the characters in this stream
    # printable ascii characters and makes the frequency of each
    # plaintext letter most closely correspond to the frequency of english
    cipher_freq = {} # frequency of the characters appearing in this stream of the ciphertext
    stream_len = 0
    min_dev = 1 # the minimum deviation from 0.065
    max_dev = 0
    for i in range(l, len(ciphertext), key_legth):
        cipher_freq[ciphertext[i]] = cipher_freq.get(ciphertext[i], 0) + 1
        stream_len += 1
    letter_deviation = 0 # sigma(q * p)
    for k in range(256):
        for letter, freq in cipher_freq.items():
            decrypted = letter ^ k
            # all characters are printable and non-digits
            #if decrypted < 32 or decrypted > 127 or chr(decrypted) in string.digits:
            if (decrypted > 126 or chr(decrypted) == '*' or chr(decrypted) == '`' or not
                                    (chr(decrypted) in string.whitespace or
                                     chr(decrypted) in string.ascii_letters or
                                     chr(decrypted) in string.punctuation)) :
                break
            letter_deviation += (freq/stream_len) * english_freq.get(decrypted, 0)
        else:
            #if letter_deviation > max_dev:
            #if (abs(english_deviation - letter_deviation) < 0.1): #ad hoc, but trying
                #keys[l].append(k)
            keys[l][k] = letter_deviation


sorted_keys = []
# sort by letter deviation for each position l 
for l in range(key_legth):
    sorted_keys.append(bytes(sorted(keys[l], key=lambda k : keys[l][k])))


# decrypt
print("probable keys = {}".format(sorted_keys))
# I guessed that the * and ` appeared way too frequently, so I tried to eliminate them
# from the beginning. Then, the last character of the ciphertext must be a valid
# punctuation mark ? . or ! and so I eliminated all the remaining probable keys
# for index 469 except that which produced a punctuation mark.
# Then, it seemed that the first word could be cryptography, so I tried it and indeed the message makes sense
guess = b'Cryptography'
key = bytes([ciphertext[i] ^ guess[i] for i in range(7)])
plaintext = bytearray(len(ciphertext))
for idx, b in enumerate(ciphertext):
    plaintext[idx] = b ^ key[idx % key_legth]

print(plaintext.decode('ascii'))
#print(plaintext)
