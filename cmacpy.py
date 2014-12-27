from CryptoPlus.Cipher import AES
import time

def cmac_aes(key, msg):
	cipher = AES.new(key, AES.MODE_CMAC)
	return cipher.encrypt(msg).encode('hex')

key128 = b"BA74B01BBEFD0402F86CF42867162C12".decode('hex')
key192 = b"65CB5887327FAF5755F18D5D133EC0D780BB89CC67900E6E".decode('hex')
key256 = b"66456475A0A4675D50F7F025B75C8CE7F4B874EEB90C374F33C62C250EDD4A15".decode('hex')
msg = b"In cryptography, a message authentication code (often MAC) is a short piece of information used to authenticate a message and to provide integrity and authenticity assurances on the message. Integrity assurances detect accidental and intentional message changes, while authenticity assurances affirm the message's origin."

t0 = time.clock()
cmac_aes(key128, msg)
t1 = time.clock() - t0
print t1
cmac_aes(key192, msg)
t2 = time.clock() - t1
print t2
cmac_aes(key256, msg)
t3 = time.clock() - t2
print t3