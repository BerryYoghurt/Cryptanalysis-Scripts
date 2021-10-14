# From the cryptography book by Katz and Lindell
# A message was encrypted using the monoalphabetic substitution cypher. Decrypt it

import string

l = "JGRMQOYGHMVBJWRWQFPWHGFFDQGFPFZRKBEEBJIZQQOCIBZKLFAFGQ\
VFZFWWEOGWOPFGFHWOLPHLRLOLFDMFGQWBLWBWQOLKFWBYLBLYLFSFLJ\
GRMQBOLWJVFPFWQVHQWFFPQOQVFPQOCFPOGFWFJIGFQVHLHLROQVFGWJ\
VFPFOLFHGQVQVFILEOGQILHQFQGIQVVOSFAFGBWQVHQWIJVWJVFPFWHG\
FIWIHZZRQGBABHZQOCGFHX"
#frequencies of single letters
di_1 = {x : 0 for x in string.ascii_uppercase}
#frequencies of digrams
di_2 = {}
for c in l:
    di_1[c] = di_1[c]+1

for i in range(len(l)-1):
    try:
        di_2[ l[i:i+2] ] = di_2[ l[i:i+2] ] + 1
    except KeyError:
        di_2[l[i:i+2]] = 1

#print ("Frequencies: ")    
#print (di_1)
#print (di_2)

#dec = {'F':'e', 'Q':'t', 'W':'a', 'G':'o', 'L':'s', 'O':'n', 'V':'h', 'H':'i',
#       'B':'r', 'P':'l', 'I':'d', 'J':'w', 'Z':'c', 'R':'u', 'E':'m', 'M':'g',
#       'S':'b', 'K':'f', 'X':'y', 'Y':'p'}

dec =  {'F':'e', 'Q':'t', 'W':'s', 'V':'h', 'O':'o', 'P':'m', 'G':'r', 'S':'w', 'A':'v',
        'L':'n', 'Z':'l', 'J':'c', 'R':'y', 'M':'p', 'Y':'g', 'B':'i', 'H':'a', 'D':'x',
        'E':'f', 'K':'d', 'I':'u', 'X':'k', 'C':'b'}
for c in l:
    try:
        print(dec[c], end='');
    except KeyError:
        print('_', end = '')
