# From https://www.coursera.org/learn/cryptography
# Problem statement: 7 messages were encrypted by XOR'ing them with
# the same key (taken from a pseudorandom distribution). Decipher them.

IS_LETTER = 0b100000
IS_SPACE = 0b010000
IS_SAME = 0b001000

ciphertext = "BB3A65F6F0034FA957F6A767699CE7FABA855AFB4F2B520AEAD612944A801E \
BA7F24F2A35357A05CB8A16762C5A6AAAC924AE6447F0608A3D11388569A1E \
A67261BBB30651BA5CF6BA297ED0E7B4E9894AA95E300247F0C0028F409A1E \
A57261F5F0004BA74CF4AA2979D9A6B7AC854DA95E305203EC8515954C9D0F \
BB3A70F3B91D48E84DF0AB702ECFEEB5BC8C5DA94C301E0BECD241954C831E \
A6726DE8F01A50E849EDBC6C7C9CF2B2A88E19FD423E0647ECCB04DD4C9D1E \
BC7570BBBF1D46E85AF9AA6C7A9CEFA9E9825CFD5E3A0047F7CD009305A71E"

sentences = [[int(x[i:i+2],base = 16) for i in range(0,len(x),2)] for x in ciphertext.split(" ")]
CHARS_PER_SENTENCE = len(sentences[0])
deductions = [[0b111000 | j for i in range(CHARS_PER_SENTENCE)] for j in range(len(sentences))] 
keys = [set() for i in range(CHARS_PER_SENTENCE)]


def decode():

    plaintext = [[]for j in range(len(sentences))]
    for i in range(CHARS_PER_SENTENCE):
        if len(keys[i]) == 0:
            for j in range(len(sentences)):
                #plaintext[j].append(ord("?"))
                plaintext[j].extend([ord(str(deductions[j][i] & 0b111)), ord('(')])
                plaintext[j].extend(ord(x) for x in str(i))
                plaintext[j].append(ord(')'))
        else:
            k = list(keys[i])
            for j in range(len(sentences)):
                plaintext[j].append(k[0] ^ sentences[j][i])
            keys[i].remove(k[0])
            for key in keys[i]: #in case there is more than one possible key
                for j in range(len(sentences)):
                    plaintext[j].append(ord("\\"),key ^ sentences[j][i])
            keys[i].add(k[0]) #return it back for decoding again

    for sentence in plaintext:
        print(bytes(sentence).decode("ascii"))



for i in range(CHARS_PER_SENTENCE):

    for j in range(1,7):

        for k in range(j-1,-1, -1):

            if len(keys[i]) == 1: # have found one certain key
                break

            xor_result = sentences[j][i] ^ sentences[k][i]
            if xor_result == 0: # same char
                deductions[j][i] = deductions[k][i] & IS_LETTER | deductions[k][i] & IS_SPACE | IS_SAME | k
            elif xor_result & 0b11000000 == 0: # 2 different letters
                deductions[k][i] = deductions[k][i] & ~IS_SPACE
                deductions[j][i] = deductions[j][i] & ~IS_SPACE
            else: # letter and space
                if deductions[k][i] & IS_SPACE == 0: # past char is not a space
                    deductions[j][i] &= ~IS_LETTER
                    key = sentences[j][i] ^ ord(" ")
                    keys[i] = {key}
                elif deductions[j][i] & IS_SPACE == 0: # current char is not a space
                    deductions[k][i] &= ~IS_LETTER
                    key = sentences[k][i] ^ ord(" ")
                    keys[i] = {key}
                else: # char i in sentence k could be a space
                    assert deductions[k][i] & IS_LETTER != 0 #if i had found out that it is a space i should have stopped!
                    assert len(keys[i]) != 1
                    # there are 2 possible keys
                    possible_keys = {sentences[j][i] ^ ord(" "), sentences[k][i] ^ ord(" ")}
                    if len(keys[i]) == 0:
                        keys[i] |= possible_keys
                    else:
                        assert len(keys[i] & possible_keys) != 0
                        keys[i] &= possible_keys

# use the information to reconstruct the plaintext
decode()

#from the previous step, some guesses are: (manual dictionary attack)
keys[0] = {sentences[3][0] ^ ord("W")}
keys[6] = {sentences[3][6] ^ ord("h")}
keys[8] = {sentences[3][8] ^ ord("u")}
keys[10] = {sentences[0][10] ^ ord("i")}
keys[17] = {sentences[0][17] ^ ord("e")}
keys[20] = {sentences[0][20] ^ ord("e")}
keys[29] = {sentences[0][29] ^ ord("n")}
keys[30] = {sentences[0][30] ^ ord(".")}

#word = 'security'
#for i in range(1,8):
#    if i == 2:
#        continue
#    keys[i + 50] = {sentences[5][i + 50] ^ ord(word[i])}

decode()
