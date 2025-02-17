#!/usr/bin/env python3

__ENCODING  = "UTF-8"
__DECODINGS = ["ISO-8859-1", "UTF-8"]

def encode(string: str):
	"""
	Encode a string.
	"""
	return string.encode(__ENCODING)

def encode_multiple(strings: list[str]):
	"""
	Encode multiple strings.
	"""
	return [encode(string) for string in strings]

def decode(bytes: bytes):
	"""
	Decode bytes.\n
	Returns an empty string and an error message on failure.
	"""
	string = ""
	message = ""
	for encoding in __DECODINGS:
		try:
			string = bytes.decode(encoding)
			message = ""
			break
		except UnicodeDecodeError as ex:
			message = str(ex)
	return string, message
