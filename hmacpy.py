from CryptoPlus.Cipher import AES
import hmac
import hashlib
import time

def hmac_sha224(key, msg):
	hash_obj = hmac.new(key = key, msg = msg, digestmod = hashlib.sha224)
	return hash_obj.hexdigest()

def hmac_sha256(key, msg):
	hash_obj = hmac.new(key = key, msg = msg, digestmod = hashlib.sha256)
	return hash_obj.hexdigest() 

def hmac_sha384(key, msg):
	hash_obj = hmac.new(key = key, msg = msg, digestmod = hashlib.sha384)
	return hash_obj.hexdigest()

def hmac_sha512(key, msg):
	hash_obj = hmac.new(key = key, msg = msg, digestmod = hashlib.sha512)
	return hash_obj.hexdigest()

def cmac_aes(key, msg):
	cipher = AES.new(key, AES.MODE_CMAC)
	return cipher.encrypt(msg).encode('hex')

key = b"ComparingTheSpeedsOfHMACAndCMAC"
key128 = b"BA74B01BBEFD0402F86CF42867162C12".decode('hex')
key192 = b"65CB5887327FAF5755F18D5D133EC0D780BB89CC67900E6E".decode('hex')
key256 = b"66456475A0A4675D50F7F025B75C8CE7F4B874EEB90C374F33C62C250EDD4A15".decode('hex')
msg = b"In cryptography, a message authentication code (often MAC) is a short piece of information used to authenticate a message and to provide integrity and authenticity assurances on the message. Integrity assurances detect accidental and intentional message changes, while authenticity assurances affirm the message's origin."

t0 = time.clock()
hmac_sha224(key, msg)
t1 = time.clock() - t0
hmac_sha256(key, msg)
t2 = time.clock() - t1
hmac_sha384(key, msg)
t3 = time.clock() - t2
hmac_sha512(key, msg)
t4 = time.clock() - t3
cmac_aes(key128, msg)
t5 = time.clock() - t4
cmac_aes(key192, msg)
t6 = time.clock() - t5
cmac_aes(key256, msg)
t7 = time.clock() - t6

print "HMAC:"
print t1
print t2
print t3
print t4
print "CMAC:"
print t5
print t6
print t7
