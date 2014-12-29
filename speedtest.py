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
	return times/sum

times = 100

if len(sys.argv) > 1:
	times = int(sys.argv[1])

start = time.clock()	
fo = open("rawdata", "wb+")
for msgsize in range(8, 1024+8, +8):
	msg = msgGenerate(msgsize*1024)
	items = [msgsize/8, count(hmac_sha224, 224), count(hmac_sha256, 256), count(hmac_sha384, 384), count(hmac_sha512, 512), count(cmac_aes, 128), count(cmac_aes, 192), count(cmac_aes, 256)]
	for item in items:
		fo.write("%s\t" %item)
	fo.write("\n")
	print msgsize/8
fo.close()
print time.clock() - start

