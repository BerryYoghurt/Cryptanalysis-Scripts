# From https://www.coursera.org/learn/cryptography
# Problem statement: The server uses CBC-MAC to authenticate messages of varying lengths
# Forge a tag for this message

from oracle import *
import sys



Oracle_Connect()

message = "I, the server, hereby agree that I will pay $100 to this student"

first_half = bytearray(message[0:32])
second_half = bytearray(message[32:])

tag = Mac(first_half, len(first_half)) # tag of the first half only

for i in range (16):
    second_half[i] ^= tag[i]

tag = Mac(second_half, len(second_half)) # tag of second xor'd with tag of first

ret = Vrfy(message, len(message), tag)
print
print ret
if (ret==1):
    print "Message verified successfully!"
else:
    print "Message verification failed."

Oracle_Disconnect()
