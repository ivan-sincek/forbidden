#!/usr/bin/env python3

from . import general, grep

import enum, typing

class Header(enum.Enum):
	"""
	Enum containing disallowed HTTP request headers.
	"""
	USER_AGENT = "User-Agent"
	COOKIE     = "Cookie"

	@classmethod
	def all(cls):
		"""
		Get all disallowed HTTP request headers.
		"""
		return [
			cls.USER_AGENT,
			cls.COOKIE
		]

	@classmethod
	def all_lower(cls):
		"""
		Get all disallowed HTTP request headers in lowercase.
		"""
		return [entry.value.lower() for entry in cls.all()]

# ----------------------------------------

def get_key_value(header: str):
	"""
	Get a key-value pair from an HTTP header.\n
	Returns an empty key-value pair on failure.
	"""
	key = ""; value = ""
	if grep.search(header, r"^[^\:]+\:.+$"):
		key, value = header.split(":", 1)
	elif grep.search(header, r"^[^\;]+\;$"):
		key, value = header.split(";", 1)
	return key.strip(), value.strip()

def format_key_value(key: str, value: typing.Any):
	"""
	Returns a key-value pair of an HTTP header as a string.
	"""
	return f"{key}: {value}" if value else f"{key};"

def to_dict_duplicate(headers: list[str]) -> dict[str, str]:
	"""
	Convert a list of HTTP headers into a dictionary while preserving duplicate HTTP headers.
	"""
	tmp = {}
	exists = set()
	for header in headers:
		key, value = get_key_value(header)
		tmp[key if key not in exists and not exists.add(key) else general.UniqueString(key)] = value
	return tmp
