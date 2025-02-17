#!/usr/bin/env python3

from . import general, grep

import typing

def get_key_value(cookie: str):
	"""
	Get a key-value pair from an HTTP cookie.\n
	Returns an empty key-value pair on failure.
	"""
	key = ""; value = ""
	if grep.search(cookie, r"^[^\=\;]+\=[^\=\;]+$|^[^\=\;]+\=$"):
		key, value = cookie.split("=", 1)
	return key.strip(), value.strip()

def format_key_value(key: str, value: typing.Any):
	"""
	Returns a key-value pair of an HTTP cookie as a string.
	"""
	return f"{key}={value}"

def to_dict_duplicate(cookies: list[str]) -> dict[str, str]:
	"""
	Convert a list of HTTP cookies into a dictionary while preserving duplicate HTTP cookies.
	"""
	tmp = {}
	exists = set()
	for cookie in cookies:
		key, value = get_key_value(cookie)
		tmp[key if key not in exists and not exists.add(key) else general.UniqueString(key)] = value
	return tmp

def to_string(cookies: list[str]):
	"""
	Convert a list of HTTP cookies into a string.
	"""
	return ("; ").join(cookies)
