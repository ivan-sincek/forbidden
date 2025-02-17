#!/usr/bin/env python3

from . import array, grep, ip, path

import enum, urllib.parse

class Scheme(enum.Enum):
	"""
	Enum containing URL schemes.
	"""
	HTTP  = "http"
	HTTPS = "https"

	@classmethod
	def all(cls):
		"""
		Get all URL schemes.
		"""
		return [
			cls.HTTP,
			cls.HTTPS
		]

	@classmethod
	def all_lower(cls):
		"""
		Get all URL schemes in lowercase.
		"""
		return [entry.value.lower() for entry in cls.all()]

	@classmethod
	def get_default_port(cls, scheme: str):
		"""
		Get the default port number for the specified URL scheme.
		"""
		mapping = {
			Scheme.HTTP : 80,
			Scheme.HTTPS: 443
		}
		return mapping[Scheme(scheme)]

# ----------------------------------------

def validate(url: str):
	"""
	Validate a URL.
	"""
	success = False
	message = ""
	tmp = urllib.parse.urlsplit(url)
	if not tmp.scheme:
		message = f"URL scheme is required: {url}"
	elif tmp.scheme not in Scheme.all_lower():
		message = f"Supported URL schemes are 'http' and 'https': {url}"
	elif not tmp.netloc:
		message = f"Invalid domain name: {url}"
	elif tmp.port and (tmp.port < 1 or tmp.port > 65535):
		message = f"Port number is out of range: {url}"
	else:
		success = True
	return success, message

# ----------------------------------------

def parse_qs(string: str):
	"""
	Parse a URL query string or fragment while preserving duplicate parameters and empty values.
	"""
	return urllib.parse.parse_qs(string, keep_blank_values = True)

def urlencode(parsed: dict[str, list[str]]):
	"""
	Stringify a parsed URL query string or fragment while preserving duplicate parameters and empty values.
	"""
	return urllib.parse.urlencode(parsed, doseq = True)

def quote(string: str):
	"""
	URL encode a string.
	"""
	return urllib.parse.quote(string)

# ----------------------------------------

def build_default_http_url(scheme: str, host: str, port: int, path: str):
	"""
	Build a default HTTP URL from the initial URL.\n
	If the initial URL scheme is not HTTP, the port number will default to 80.
	"""
	if scheme != Scheme.HTTP.value:
		port = Scheme.get_default_port(Scheme.HTTP.value)
	return f"{Scheme.HTTP.value}://{host}:{port}{path}"

def build_default_https_url(scheme: str, host: str, port: int, path: str):
	"""
	Build a default HTTPS URL from the initial URL.\n
	If the initial URL scheme is not HTTPS, the port number will default to 443.
	"""
	if scheme != Scheme.HTTPS.value:
		port = Scheme.get_default_port(Scheme.HTTPS.value)
	return f"{Scheme.HTTPS.value}://{host}:{port}{path}"

# ----------------------------------------

class URL:

	def __init__(self, url: str, ignore_parameters = False):
		"""
		Class for storing URL details.
		"""
		tmp               = urllib.parse.urlsplit(url)
		self.scheme       = tmp.scheme.lower()
		self.port         = tmp.port or Scheme.get_default_port(self.scheme)
		self.domain       = self.Domain(self.scheme, grep.replace(tmp.netloc, f":{self.port}$"), self.port)
		self.ip           = self.IP(self.scheme, ip.get(self.domain.domain.rsplit("@", 1)[-1]), self.port)
		self.query_string = self.QueryString(tmp.query, ignore_parameters)
		self.fragment     = self.Fragment(tmp.fragment, ignore_parameters)
		self.path         = self.Path(tmp.path, self.query_string, self.fragment)
		self.full         = self.Full(self.scheme, self.domain, self.ip, self.port, self.path)

	def is_ip(self):
		"""
		Check if the initial URL host is an IP address.
		"""
		return self.domain.domain == self.ip.ip

	def is_https(self):
		"""
		Check if the initial URL scheme is HTTPS.
		"""
		return self.scheme == Scheme.HTTPS.value

	class Domain:

		def __init__(self, scheme: str, domain: str, port: int):
			"""
			Class for storing domain name details.
			"""
			self.domain             = domain
			self.domain_port        = f"{domain}:{port}"
			self.scheme_domain      = f"{scheme}://{domain}"
			self.scheme_domain_port = f"{scheme}://{domain}:{port}"
			self.domains            = [self.domain, self.domain_port]
			self.scheme_domains     = [self.scheme_domain, self.scheme_domain_port]

	class IP:

		def __init__(self, scheme: str, ip: str, port: int):
			"""
			Class for storing IP address details.
			"""
			self.ip             = ip
			self.ip_port        = f"{ip}:{port}"
			self.scheme_ip      = f"{scheme}://{ip}"
			self.scheme_ip_port = f"{scheme}://{ip}:{port}"
			self.ips            = [self.ip, self.ip_port]
			self.scheme_ips     = [self.scheme_ip, self.scheme_ip_port]

	class QueryString:

		def __init__(self, query_string: str, ignore = False):
			"""
			Class for storing URL query string details.
			"""
			self.parsed = {}
			self.string = ""
			"""
			If exists, a string starting with '?'.
			"""
			if not ignore and query_string:
				self.parsed = parse_qs(query_string)
				self.string = f"?{urlencode(self.parsed)}"

	class Fragment:

		def __init__(self, fragment: str, ignore = False):
			"""
			Class for storing URL fragment details.\n
			At the moment, there are no tests related to the URL fragment.
			"""
			self.string = ""
			"""
			If exists, a string starting with '#'.
			"""
			if not ignore and fragment:
				self.string = f"#{fragment}"

	class Path:

		def __init__(self, path_no_parameters: str, query_string: "URL.QueryString", fragment: "URL.Fragment"):
			"""
			Class for storing URL path details.
			"""
			self.path_no_parameters = path.replace_multiple_slashes(path_no_parameters)
			"""
			If exists, a string starting with '/'.
			"""
			self.path               = self.path_no_parameters + query_string.string + fragment.string
			"""
			If exists, a string starting with '/'.
			"""

	class Full:

		def __init__(self, scheme: str, domain: "URL.Domain", ip: "URL.IP", port: int, path: "URL.Path"):
			"""
			Class for storing full URL details.
			"""
			self.initial = self.Host(domain, ip, path)
			self.domain  = self.Scheme(scheme, domain.domain, port, path.path)
			self.ip      = self.Scheme(scheme, ip.ip, port, path.path)

		class Host:

			def __init__(self, domain: "URL.Domain", ip: "URL.IP", path: "URL.Path"):
				"""
				Class for storing full URL details based on the URL host.
				"""
				self.domain = domain.scheme_domain_port + path.path
				self.ip     = ip.scheme_ip_port + path.path
				self.all    = array.unique([self.domain, self.ip])

		class Scheme:

			def __init__(self, scheme: str, host: str, port: int, path: str):
				"""
				Class for storing full URL details based on the URL scheme.
				"""
				self.https = build_default_https_url(scheme, host, port, path)
				self.http  = build_default_http_url(scheme, host, port, path)
				self.all   = [self.https, self.http]
