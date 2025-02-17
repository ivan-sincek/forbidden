#!/usr/bin/env python3

import socket

def get(fqdn: str):
	"""
	Get the IPv4 address for the specified FQDN.\n
	Returns an empty string on failure.
	"""
	ip = ""
	try:
		if fqdn:
			ip = socket.gethostbyname(fqdn)
	except socket.error:
		pass
	return ip
