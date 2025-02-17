#!/usr/bin/env python3

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives            import serialization

def create_private_key():
	"""
	Create a random RSA private key.
	"""
	private_key = rsa.generate_private_key(65537, 2048)
	return private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
