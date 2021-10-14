# From https://www.coursera.org/learn/cryptography
# Problem Statement: You know that message authentication is done in the following way:
# To sign a message m of length exactly 63 bytes, set M = 0x00 m 0x00 m
# and then compute the signature M^d mod N.
#(If m is shorter than 63 bytes, 0-bytes are first preprended to make its length exactly 63 bytes.

from oracle import *
from helper import *

n = 119077393994976313358209514872004186781083638474007212865571534799455802984783764695504518716476645854434703350542987348935664430222174597252144205891641172082602942313168180100366024600206994820541840725743590501646516068078269875871068596540116450747659687492528762004294694507524718065820838211568885027869

e = 65537

Oracle_Connect()

msg = "Crypto is hard --- even schemes that look complex can be broken"

m = ascii_to_int(msg)

# Obtain the signature of 1 to help later
# The inverse of the signature must exist because
# it is exactly (16^64 + 1)^(e*d - d) mod N
m_1 = 1
sigma_1 = Sign(m_1)
sigma_1_inv = modinv(sigma_1, n)

# Factorise m
f = 2
while f * f <= m:
    if m % f == 0:
        break
    f += 1

if m % f != 0:
    print "The message is prime!"
    raise SystemExit

sigma_f = Sign(f)
sigma_q = Sign(m // f)

sigma_m = (sigma_f * sigma_q * sigma_1_inv) % n

if Verify(m, sigma_m):
    print "mesage authenticated successfully"
else:
    print "signature not correct"

Oracle_Disconnect()
