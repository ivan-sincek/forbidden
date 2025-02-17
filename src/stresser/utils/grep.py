#!/usr/bin/env python3

import regex as re

__FLAGS = re.MULTILINE | re.IGNORECASE

def validate(query: str):
	"""
	Validate a regular expression.
	"""
	success = False
	message = ""
	try:
		re.compile(query)
		success = True
	except re.error:
		message = f"Invalid RegEx: {query}"
	return success, message

def find(string: str, query: str):
	"""
	Extract all matches from a string using the specified RegEx pattern.
	"""
	return re.findall(query, string, flags = __FLAGS)

def search(string: str, query: str):
	"""
	Check if there are any matches in a string using the specified RegEx pattern.
	"""
	return bool(re.search(query, string, flags = __FLAGS))

def replace(string: str, query: str, new = ""):
	"""
	Replace all matches in a string using the specified RegEx pattern with a new value.
	"""
	return re.sub(query, new, string, flags = __FLAGS)
