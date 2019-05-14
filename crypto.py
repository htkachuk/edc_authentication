from hashlib import sha256
import ecdsa
import codecs
import binascii
from ecdsa.curves import SECP256k1
from random import random

def createPublicKeyECDSA(login, passwd):
	privateKey = sha256(bytes((login+passwd), 'utf-8')).hexdigest()
	privateKey = codecs.decode(privateKey, 'hex')
	sk = ecdsa.SigningKey.from_string(privateKey, curve=SECP256k1)
	vk = sk.get_verifying_key()
	publicKey = binascii.hexlify(vk.to_string()).decode()
	return publicKey

def checkPublicKeyECDSA(publicKey, login, passwd, client_num):
	privateKey = sha256(bytes((login+passwd), 'utf-8')).hexdigest()
	privateKey = codecs.decode(privateKey, 'hex')
	server_num = random()
	message = sha256(bytes((str(client_num)+str(server_num)), 'utf-8')).hexdigest()
	message = codecs.decode(message, 'hex')
	sk = ecdsa.SigningKey.from_string(privateKey, curve=ecdsa.SECP256k1)
	sig = sk.sign_digest(message)
	try:
		publicKey = codecs.decode(publicKey, 'hex')
	except:
		return False
	vk = ecdsa.VerifyingKey.from_string(publicKey, curve=ecdsa.SECP256k1)
	try:
		vk.verify_digest(sig, message)
		return True
	except:
		return False

