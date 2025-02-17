#!/usr/bin/env python3

from . import array, grep

SEP = "/"

def replace_multiple_slashes(path_no_parameters: str):
	"""
	Replace multiple consecutive forward slashes with a single forward slash.\n
	For example, replace '//' with '/', etc.
	"""
	return grep.replace(path_no_parameters, r"\/{2,}", SEP)

def prepend_slash(path: str):
	"""
	Append a single forward slash if one does not already exist.
	"""
	if path and not path.startswith(SEP):
		path = SEP + path
	return path

def remove_trailing_slash(root_url: str):
	"""
	Remove a single forward slash from the end if one already exists.
	"""
	if root_url and root_url.endswith(SEP):
		root_url = root_url[:-1]
	return root_url

def join(root_url: str, path: str):
	"""
	Concatenate a root URL with the specified URL path.
	"""
	return remove_trailing_slash(root_url) + prepend_slash(path) if path else root_url

def join_multiple(root_url: str, paths: list[str]):
	"""
	Concatenate a root URL with the specified URL paths.\n
	Returns a unique list.
	"""
	return array.unique(join(root_url, path) for path in paths) if paths else [root_url]

def expand(path_no_parameters: str, query_string = "", fragment = ""):
	"""
	Expand a relative URL path.\n
	For example, from any path to '[/path/, /path, path/, path]', etc., or if the path is an empty string, to '[/]'.\n
	If specified, the query string must start with '?'.\n
	If specified, the fragment must start with '#'.\n
	Returns a unique list of relative URL paths with and without the URL parameters.
	"""
	path = path_no_parameters.strip(SEP)
	tmp = [SEP + path + SEP, SEP + path, path + SEP, path] if path else [SEP]
	if query_string or fragment:
		tmp = [entry + query_string + fragment for entry in tmp] + tmp
	return array.unique(tmp)

def get_recursive(path_no_parameters: str):
	"""
	Get all relative URL paths recursively for each directory in the URL path with and without the ending forward slash.\n
	Returns a unique list.
	"""
	end_no_sep = ""
	end_sep = SEP
	tmp = [end_no_sep, end_sep]
	path = path_no_parameters.strip(SEP)
	if path:
		for directory in path.split(SEP):
			end_no_sep += SEP + directory
			end_sep += directory + SEP
			tmp.extend([end_no_sep, end_sep])
	tmp.reverse()
	return array.unique(tmp)
