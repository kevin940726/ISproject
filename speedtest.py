from CryptoPlus.Cipher import AES
import hmac
import hashlib
import time
from functools import partial
from Crypto import Random
import sys

def hmac_sha224(key, msg):
	start =  time.clock()
	hash_obj = hmac.new(key = key, msg = msg, digestmod = hashlib.sha224)
	hash_obj.hexdigest()
	return time.clock()-start

def hmac_sha256(key, msg):
	start =  time.clock()
	hash_obj = hmac.new(key = key, msg = msg, digestmod = hashlib.sha256)
	hash_obj.hexdigest() 
	return time.clock()-start

def hmac_sha384(key, msg):
	start = time.clock()
	hash_obj = hmac.new(key = key, msg = msg, digestmod = hashlib.sha384)
	hash_obj.hexdigest()
	return time.clock()-start

def hmac_sha512(key, msg):
	start = time.clock()
	hash_obj = hmac.new(key = key, msg = msg, digestmod = hashlib.sha512)
	hash_obj.hexdigest()
	return time.clock()-start

def cmac_aes(key, msg):
	start = time.clock()
	cipher = AES.new(key.decode('hex'), AES.MODE_CMAC)
	cipher.encrypt(msg).encode('hex')
	return time.clock()-start

def keyGenerate(bits):
	return Random.get_random_bytes(bits/8).encode('hex')

def msgGenerate(bits):
	return Random.get_random_bytes(bits/8).encode('hex')

def msgRepeat(keySize):	
	start =  time.clock()
	fo = open("hmacMsg"+str(keySize), "wb+")
	fo.write("\tHMAC SHA-224\tHMAC SHA-256\tHMAC SHA-384\tHMAC SHA-512\tCMAC AES-"+str(keySize)+"\n")

	for msgSize in range(8, 1024+8, +8):
		msg = msgGenerate(msgSize*1024)
		key = keyGenerate(keySize)
		items = [msgSize/8, 1/hmac_sha224(key, msg), 1/hmac_sha256(key, msg), 1/hmac_sha384(key, msg), 1/hmac_sha512(key, msg), 1/cmac_aes(key, msg)]
		for item in items:
			fo.write("%s\t" %item)
		fo.write("\n")
	fo.close()
	print str(time.clock()-start) + " seconds for total."
	print "hmacMsg and cmac for key size of " + str(keySize) + " done."

def msgRepeatCmac():
	start =  time.clock()	
	fo = open("cmacMsg", "wb+")
	fo.write("\tCMAC AES-128\tCMAC AES-192\tCMAC AES-256\n")

	for msgSize in range(8, 1024+8, +8):
		msg = msgGenerate(msgSize*1024)
		key128 = keyGenerate(128)
		key192 = keyGenerate(192)
		key256 = keyGenerate(256)
		items = [msgSize/8, 1/cmac_aes(key128, msg), 1/cmac_aes(key192, msg), 1/cmac_aes(key256, msg)]
		for item in items:
			fo.write("%s\t" %item)
		fo.write("\n")
	fo.close()
	print str(time.clock()-start) + " seconds for total."
	print "cmacMsg done."

def timesRepeat(keySize):
	start =  time.clock()
	fo = open("hmac"+str(keySize), "wb+")
	fo.write("\tHMAC SHA-224\tHMAC SHA-256\tHMAC SHA-384\tHMAC SHA-512\tCMAC AES-"+str(keySize)+"\n")

	for times in range(0, n):
		msg = msgGenerate(msgsize)
		key = keyGenerate(keySize)
		items = [times+1, 1/hmac_sha224(key, msg), 1/hmac_sha256(key, msg), 1/hmac_sha384(key, msg), 1/hmac_sha512(key, msg), 1/cmac_aes(key, msg)]
		for item in items:
			fo.write("%s\t" %item)
		fo.write("\n")
	fo.close()
	print str(time.clock()-start) + " seconds for total."
	print "hmac repeat for "+str(n)+" times with key size of "+str(keySize)+" done."

def timesRepeatCmac():
	start =  time.clock()
	fo = open("cmac", "wb+")
	fo.write("\tCMAC AES-128\tCMAC AES-192\tCMAC AES-256\n")

	for times in range(0, n):	
		msg = msgGenerate(msgsize)
		key128 = keyGenerate(128)
		key192 = keyGenerate(192)
		key256 = keyGenerate(256)
		items = [times+1, 1/cmac_aes(key128, msg), 1/cmac_aes(key192, msg), 1/cmac_aes(key256, msg)]
		for item in items:
			fo.write("%s\t" %item)
		fo.write("\n")
	fo.close()
	print str(time.clock()-start) + " seconds for total."
	print "cmac repeat for "+str(n)+" times done."

# Initialize.
n = 100
msgsize = 2048
# Load arguments for parameters.
if len(sys.argv) == 2:
	n = int(sys.argv[1])
elif len(sys.argv) == 3:
	msgsize = int(sys.argv[2])


# Repeat 'n' times for each algorithm.
timesRepeat(128)
timesRepeat(192)
timesRepeat(256)
timesRepeatCmac()
# Repeat 8 ~ 1024(*1024bits) times for each message size.
msgRepeat(128)
msgRepeat(192)
msgRepeat(256)
msgRepeatCmac()

print "For HMAC and CMAC comparing test with each key size for a number of times, check out the output file named 'hmac[keySize]'."
print "For CMAC comparing with each other for a number of times, check out the output file 'cmac'."
print "For HMAC and CMAC comparing with each key size for different mwssage size, check out the output file named 'hmacMsg[keySize]'."
print "For CMAC comparing with each other for different message size, check out the output 'cmacMsg'."
