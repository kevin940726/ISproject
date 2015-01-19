Task Description
====================
	Your task is to compare the speeds of HMAC and CMAC (Pages 390-391 and 395 of [Stallings 2014] respectively). For HMAC please use one of the SHA-2 algorithms as the hash function and for CMAC please use AES. Try to be rigorous in the design of the evaluation processes, in particular the test cases. It should be interesting to experiment with different hash-code sizes for the SHA-2 function and different key sizes for AES. For the ease of demonstration, a Web interface to the evaluation processes is highly desirable. You may reuse free or open source software implementation of the various algorithms. Be sure to give due credits and provide proper references.
	Consult the general guidelines (also on the course website) for deadlines and regulations.
	
	The Following is the Python code of the implementation of the method.
	For HMAC with SHA-224, SHA-256, SHA-384, SHA-512, the Python code is as follow:
```
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
```
	While ``key`` refers to the key of the method, and ``msg`` is the sample message of the method. We use the standard library of Pyhton ``hmac`` and ``hashlib``. For time calculating, we use Python ``time.clock()`` rather than ``time.time()`` which is more precise in UNIX system than the other. The above functions will return the time of generating the cipher code.
	
	For CMAC, we use the Pyhton code as follow:
```
def cmac_aes(key, msg):
	start = time.clock()
	cipher = AES.new(key.decode('hex'), AES.MODE_CMAC)
	cipher.encrypt(msg).encode('hex')
	return time.clock()-start
```
	Like HMAC, ``key`` and ``msg`` refers to key and messages used for CMAC-AES repectively, while the function return the time spent for the method as well.
