Task Description
====================
Your task is to compare the speeds of HMAC and CMAC (Pages 390-391 and 395 of [Stallings 2014] respectively). For HMAC please use one of the SHA-2 algorithms as the hash function and for CMAC please use AES. Try to be rigorous in the design of the evaluation processes, in particular the test cases. It should be interesting to experiment with different hash-code sizes for the SHA-2 function and different key sizes for AES. For the ease of demonstration, a Web interface to the evaluation processes is highly desirable. You may reuse free or open source software implementation of the various algorithms. Be sure to give due credits and provide proper references.
Consult the general guidelines (also on the course website) for deadlines and regulations.
	
The Following is the Python code of the implementation of the method.
For HMAC with SHA-224, the Python code is as follow:
'''
	def hmac_sha224(key, msg):
		start =  time.clock()
		hash_obj = hmac.new(key = key, msg = msg, digestmod = hashlib.sha224)
		hash_obj.hexdigest()
		return time.clock()-start
'''
