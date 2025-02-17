#!/usr/bin/env python3

import os

def is_directory(directory: str):
	"""
	Returns 'True' if 'directory' exists and is a regular directory.
	"""
	return os.path.isdir(directory)
