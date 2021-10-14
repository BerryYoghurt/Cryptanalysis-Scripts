# From https://www.coursera.org/learn/cryptography
# Problem Statement: A message has been encrypted using AES in CBC mode and PKCS #7 padding.
# decrypt the message.

from oracle import *
import sys

BLOCK_LENGTH = 16

if len(sys.argv) < 2:
    print "Usage: python sample.py <filename>"
    sys.exit(-1)

f = open(sys.argv[1])
data = f.read()
f.close()

ctext = [(int(data[i:i+2],16)) for i in range(0, len(data), 2)]

msg = ctext[:]

Oracle_Connect()

# find beginning of padding
p = BLOCK_LENGTH
curr_byte = - 2 * BLOCK_LENGTH

while True:
    assert curr_byte < - BLOCK_LENGTH

    msg[curr_byte] ^= 0xFF
    rc = Oracle_Send(msg, 3)
    msg[curr_byte] ^= 0xFF

    if rc == 0:
        break
    p -= 1
    curr_byte += 1

curr_byte -= 1
p += 1

# decrypt
MSG_LEN = len(ctext)
curr_byte += MSG_LEN # count in positives to avoid confusion
ptext = [ord(' ') for i in range (MSG_LEN)]

while curr_byte >= 0:
    if p > BLOCK_LENGTH:
        p = 1
        msg = ctext[:to_block * BLOCK_LENGTH]
        MSG_LEN -= BLOCK_LENGTH

    for i in range(curr_byte + 1, MSG_LEN - BLOCK_LENGTH):
        msg[i] ^= p ^ (p - 1)
    
    for mod in range(256):
        msg[curr_byte] = ctext[curr_byte] ^ mod
        rc = Oracle_Send(msg, MSG_LEN / BLOCK_LENGTH)
        if rc == 1:
            ptext[curr_byte] = p ^ mod
            break

    curr_byte -= 1
    p += 1

ans = ""
for i in ptext:
    ans += chr(i)
print "Decrypted Message is ", ans

Oracle_Disconnect()
