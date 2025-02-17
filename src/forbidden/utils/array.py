#!/usr/bin/env python3

def unique(array: list[str]):
	"""
	Remove duplicates from a list.
	"""
	seen = set()
	return [x for x in array if not (x in seen or seen.add(x))]

def remove_empty_strings(array: list[str]) -> list[str]:
	"""
	Strip whitespace from each string in a list, and remove empty strings.
	"""
	tmp = []
	for entry in array:
		entry = entry.strip()
		if entry:
			tmp.append(entry)
	return tmp

def to_array(value: str | list[str]):
	"""
	Returns a value as a list if the value is not one already.
	"""
	return value if isinstance(value, list) else [value]
