#!/usr/bin/env python3

from . import array, grep, path, url

import base64, json, jwt as pyjwt, typing

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

# ----------------------------------------

def to_hex(string: str):
	"""
	Hexadecimal encode all alphanumeric characters a string.
	"""
	tmp = ""
	for character in string:
		if character.isalnum():
			character = f"%{format(ord(character), 'x')}"
		tmp += character
	return tmp

def to_unicode(string: str, case_sensitive = False):
	"""
	Replace each alphanumeric characters in a string with its corresponding Unicode modifier.\n
	Not all alphanumeric characters are supported.
	"""
	modifiers = {
		"a": "\u1d2c",
		"b": "\u1d2e",
		"d": "\u1d30",
		"e": "\u1d31",
		"g": "\u1d33",
		"h": "\u1d34",
		"i": "\u1d35",
		"j": "\u1d36",
		"k": "\u1d37",
		"l": "\u1d38",
		"m": "\u1d39",
		"n": "\u1d3a",
		"o": "\u1d3c",
		"p": "\u1d3e",
		"r": "\u1d3f",
		"t": "\u1d40",
		"u": "\u1d41",
		"w": "\u1d42",
		"1": "\u2460",
		"2": "\u2461",
		"3": "\u2462",
		"4": "\u2463",
		"5": "\u2464",
		"6": "\u2465",
		"7": "\u2466",
		"8": "\u2467",
		"9": "\u2468"
	}
	if case_sensitive:
		for old, new in modifiers.items():
			if old in string:
				string = string.replace(old, new)
	else:
		lower = string.lower()
		for old, new in modifiers.items():
			if old in lower:
				string = grep.replace(string, old, new)
	return string

# ----------------------------------------

def toggle(string: str):
	"""
	Change the case of alphabetical characters in a string, alternating between uppercase and lowercase.
	"""
	tmp = ""
	upper = False
	for character in string:
		if character.isalpha():
			upper = character.isupper()
			break
	for character in string:
		if character.isalpha():
			character = character.lower() if upper else character.upper()
			upper = not upper
		tmp += character
	return tmp

def capitalize(string: str):
	"""
	Capitalize a string starting from the first alphabetical character.
	"""
	tmp = ""
	changed = False
	for character in string.lower():
		if not changed and character.isalpha():
			character = character.upper()
			changed = True
		tmp += character
	return tmp

# ----------------------------------------

def transform_host(host: str):
	"""
	Get a list of transformed and encoded URL hosts, including the initial one.\n
	Returns a unique list.
	"""
	tmp = [host, host.lower(), host.upper(), toggle(host), capitalize(host), url.quote(to_unicode(host))]
	tmp = tmp + [to_hex(entry) for entry in tmp[:-1]]
	return array.unique(tmp)

def transform_path(path_no_parameters: str):
	"""
	Get a list of transformed and encoded relative URL paths, including the initial one.\n
	Returns a unique list.
	"""
	tmp = []
	directory = path_no_parameters.strip(path.SEP)
	if not directory:
		tmp = [path_no_parameters]
	else:
		directory = directory.rsplit(path.SEP, 1)
		last      = directory[-1]
		tmp       = [last, last.lower(), last.upper(), toggle(last), capitalize(last), url.quote(to_unicode(last))]
		tmp       = tmp + [to_hex(entry) for entry in tmp[:-1]]
		prepend   = path.SEP if len(directory) < 2 else path.SEP + directory[0] + path.SEP
		append    = path.SEP if path_no_parameters.endswith(path.SEP) else ""
		tmp       = [prepend + entry + append for entry in tmp]
	return array.unique(tmp)

# ----------------------------------------

def b64(string: str):
	"""
	Base64 encode a string.
	"""
	return base64.b64encode((string).encode(__ENCODING)).decode(__ENCODING)

def b64_credentials(username: str, password: str):
	"""
	Base64 encode credentials as used in basic authentication/authorization.
	"""
	return b64(f"{username}:{password}")

def b64_payload(payload: dict[str, typing.Any]):
	"""
	Base64 encode a payload as used in JWTs.
	"""
	return b64(json.dumps(payload, separators = (",", ":"))).rstrip("=")

def jwt(alg: str, key: str, payload: dict[str, typing.Any] = None, headers: dict[str, typing.Any] = None):
	"""
	JWT encode.
	"""
	return pyjwt.encode(payload or {}, key, alg, headers or {})
