#!/usr/bin/env python3

from . import grep

SEP = "/"

def replace_multiple_slashes(path_no_parameters: str):
	"""
	Replace multiple consecutive forward slashes with a single forward slash.\n
	For example, replace '//' with '/', etc.
	"""
	return grep.replace(path_no_parameters, r"\/{2,}", SEP)
