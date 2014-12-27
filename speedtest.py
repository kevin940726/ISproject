from CryptoPlus.Cipher import AES
import hmac
import hashlib
import time
from functools import partial
from Crypto import Random
import sys

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
	cipher = AES.new(key.decode('hex'), AES.MODE_CMAC)
	return cipher.encrypt(msg).encode('hex')

def keyGenerate(bits):
	return Random.get_random_bytes(bits/8).encode('hex')

def msgGenerate(bits):
	return Random.get_random_bytes(bits/8).encode('hex')

def count(alg, keysize):
	sum = 0.0
	for i in range(0, times):
		key = keyGenerate(keysize)
		t0 = time.clock()
		alg(key, msg)
		sum += time.clock() - t0
	return sum/times

times = 100
msgsize = 1024

if len(sys.argv) > 1:
	times = int(sys.argv[1])
	msgsize = int(sys.argv[2])

start = time.clock()	
fo = open("rawdata", "wb+")
for msgsize in range(1024, 1024*1024, +1024*8):
	msg = msgGenerate(msgsize)
	items = [1/count(hmac_sha224, 224), 1/count(hmac_sha256, 256), 1/count(hmac_sha384, 384), 1/count(hmac_sha512, 512), 1/count(cmac_aes, 128), 1/count(cmac_aes, 192), 1/count(cmac_aes, 256)]
	for item in items:
		fo.write("%s\t" %item)
	fo.write("\n")
	print msgsize/(1024*8)
fo.close()
print time.clock() - start

