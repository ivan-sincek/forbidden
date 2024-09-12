#!/usr/bin/env python3

import alive_progress, argparse, colorama, concurrent.futures, copy, datetime, io, json, os, pycurl, random, regex as re, requests, socket, subprocess, sys, tabulate, tempfile, termcolor, threading, urllib.parse

colorama.init(autoreset = True)

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# ----------------------------------------

class Stopwatch:

	def __init__(self):
		self.__start = datetime.datetime.now()

	def stop(self):
		self.__end = datetime.datetime.now()
		print(("Script has finished in {0}").format(self.__end - self.__start))

stopwatch = Stopwatch()

# ----------------------------------------

default_quotes = "'" # NOTE: Default quotes for the JSON 'command' attribute in the results.

def escape_quotes(value):
	return str(value).replace(default_quotes, ("\\{0}").format(default_quotes))

def set_param(value, param = ""):
	value = default_quotes + escape_quotes(value) + default_quotes
	if param:
		value = ("{0} {1}").format(param, value)
	return value

# ----------------------------------------

def get_header_key_value(header):
	key = ""; value = ""
	if re.search(r"^[^\:]+\:.+$", header):
		key, value = header.split(":", 1)
	elif re.search(r"^[^\;]+\;$", header):
		key, value = header.split(";", 1)
	return key.strip(), value.strip()

def format_header_key_value(key, value):
	return ("{0}: {1}").format(key, value) if value else ("{0};").format(key)

def get_cookie_key_value(cookie):
	key = ""; value = ""
	if re.search(r"^[^\=\;]+\=[^\=\;]+$|^[^\=\;]+\=$", cookie):
		key, value = cookie.split("=", 1)
	return key.strip(), value.strip()

def format_cookie_key_value(key, value):
	return ("{0}={1}").format(key, value)

def array_to_dict(array, separator):
	tmp = {}
	for entry in array:
		key, value = entry.split(separator)
		tmp[key] = value
	return tmp

# ----------------------------------------

def get_base_https_url(scheme, dnp, port, full_path):
	return ("https://{0}:{1}{2}").format(dnp, port if scheme == "https" else 443, full_path)

def get_base_http_url(scheme, dnp, port, full_path):
	return ("http://{0}:{1}{2}").format(dnp, port if scheme == "http" else 80, full_path)

def get_all_domains(scheme, dnps, port): # NOTE: Can extends both, domain names and IPs.
	if not isinstance(dnps, list):
		dnps = [dnps]
	tmp = []
	for dnp in dnps:
		tmp.extend([
			dnp,
			("{0}:{1}").format(dnp, port),
			("{0}://{1}").format(scheme, dnp),
			("{0}://{1}:{2}").format(scheme, dnp, port)
		])
	return unique(tmp)

# ----------------------------------------

path_const = "/"

def replace_multiple_slashes(path):
	return re.sub(r"\/{2,}", path_const, path)

def prepend_slash(path):
	if not path.startswith(path_const):
		path = path_const + path
	return path

def append_paths(bases, paths):
	if not isinstance(bases, list):
		bases = [bases]
	if not isinstance(paths, list):
		paths = [paths]
	tmp = []
	for base in bases:
		if base:
			for path in paths:
				tmp.append(base.rstrip(path_const) + prepend_slash(path) if path else base)
	return unique(tmp)

def extend_path(path, query_string = "", fragment = ""):
	tmp = []
	path = path.strip(path_const)
	if not path:
		tmp.append(path_const)
	else:
		tmp.extend([path_const + path + path_const, path + path_const, path_const + path, path])
	if query_string or fragment:
		for i in range(len(tmp)):
			tmp[i] = tmp[i] + query_string + fragment
	return unique(tmp)

# ----------------------------------------

def print_white(text):
	termcolor.cprint(text, "white")

def print_cyan(text):
	termcolor.cprint(text, "cyan")

def print_red(text):
	termcolor.cprint(text, "red")

def print_yellow(text):
	termcolor.cprint(text, "yellow")

def print_green(text):
	termcolor.cprint(text, "green")

def print_time(text):
	print(("{0} - {1}").format(datetime.datetime.now().strftime("%H:%M:%S"), text))

default_encoding = "ISO-8859-1" # NOTE: ISO-8859-1 works better than UTF-8 when accessing files.

default_encoding_array = ["UTF-8", default_encoding] # NOTE: For HTTP requests/responses, try UTF-8 first.

def decode(value):
	tmp = ""
	error = ""
	for encoding in unique(default_encoding_array):
		try:
			tmp = value.decode(encoding)
			error = ""
			break
		except UnicodeDecodeError as ex:
			error = ex
			continue
	return (tmp, error)

def jdump(data):
	return json.dumps(data, indent = 4, ensure_ascii = False)

def pop(array, keys):
	for obj in array:
		for key in keys:
			obj.pop(key, None)
	return array

# ----------------------------------------

class uniquestr(str):
	__lower = None
	def __hash__(self):
		return id(self)
	def __eq__(self, other):
		return self is other
	def lower(self):
		if self.__lower is None:
			lower = str.lower(self)
			if str.__eq__(lower, self): 
				self.__lower = self
			else:
				self.__lower = uniquestr(lower)
		return self.__lower

# ----------------------------------------

def unique(sequence):
	seen = set()
	return [x for x in sequence if not (x in seen or seen.add(x))]

def write_file(data, out):
	confirm = "yes"
	if os.path.isfile(out):
		print(("'{0}' already exists").format(out))
		confirm = input("Overwrite the output file (yes): ")
	if confirm.lower() == "yes":
		try:
			open(out, "w").write(data)
			print(("Results have been saved to '{0}'").format(out))
		except FileNotFoundError:
			print(("Cannot save results to '{0}'").format(out))

# ----------------------------------------

default_user_agent = "Stresser/12.3"

def get_all_user_agents():
	tmp = []
	file = os.path.join(os.path.abspath(os.path.split(__file__)[0]), "user_agents.txt")
	if os.path.isfile(file) and os.access(file, os.R_OK) and os.stat(file).st_size > 0:
		with open(file, "r", encoding = default_encoding) as stream:
			for line in stream:
				line = line.strip()
				if line:
					tmp.append(line)
	return tmp if tmp else [default_agent]

def get_random_user_agent():
	tmp = get_all_user_agents()
	return tmp[random.randint(0, len(tmp) - 1)]

# ----------------------------------------

ERROR     =  0
IGNORED   = -1
DUPLICATE = -2

class Stresser:

	def __init__(self, url, ignore_qsf, ignore_requests, force, headers, cookies, ignore_regex, content_lengths, request_timeout, repeat, threads, user_agents, proxy, status_codes, show_table, directory, debug):
		# --------------------------------
		# NOTE: User-supplied input.
		self.__url             = self.__parse_url(url, ignore_qsf)
		self.__force           = force
		self.__headers         = headers
		self.__cookies         = cookies
		self.__ignore_regex    = ignore_regex
		self.__content_lengths = content_lengths
		self.__repeat          = repeat
		self.__threads         = threads
		self.__user_agents     = user_agents
		self.__user_agents_len = len(self.__user_agents)
		self.__proxy           = proxy
		self.__status_codes    = status_codes
		self.__show_table      = show_table
		self.__directory       = directory
		self.__debug           = debug
		# --------------------------------
		# NOTE: cURL configuration.
		self.__curl            = ignore_requests
		self.__verify          = False # NOTE: Ignore SSL/TLS verification.
		self.__allow_redirects = True
		self.__max_redirects   = 10
		self.__connect_timeout = request_timeout
		self.__read_timeout    = request_timeout
		self.__regex_flags     = re.MULTILINE | re.IGNORECASE
		# --------------------------------
		self.__error                = False
		self.__print_lock           = threading.Lock()
		self.__default_method       = "GET"
		self.__allowed_methods      = []
		self.__collection           = []
		self.__identifier           = 0
		self.__exclude_from_dump    = ["raw", "proxy", "code", "length", "response", "response_headers"]
		self.__exclude_from_results = ["raw", "proxy", "response", "response_headers", "curl"]

	def __parse_url(self, url, ignore_qsf = False, case_sensitive = False):
		url      = urllib.parse.urlsplit(url)
		scheme   = url.scheme.lower()
		port     = int(url.port) if url.port else (443 if scheme == "https" else 80)
		domain   = url.netloc if url.port else ("{0}:{1}").format(url.netloc, port)
		domain   = domain.lower() if not case_sensitive else domain
		path     = replace_multiple_slashes(url.path)
		# --------------------------------
		query    = {}
		fragment = {}
		query["parsed"   ] = {} if ignore_qsf else urllib.parse.parse_qs(url.query, keep_blank_values = True)
		query["full"     ] = ("?{0}").format(urllib.parse.urlencode(query["parsed"], doseq = True)) if query["parsed"] else ""
		fragment["parsed"] = {} # NOTE: Not used.
		fragment["full"  ] = ("#{0}").format(url.fragment) if url.fragment else ""
		# --------------------------------
		tmp                          = {}
		tmp["scheme"               ] = scheme
		tmp["port"                 ] = port
		# --------------------------------
		tmp["domain_no_port"       ] = domain.split(":", 1)[0]
		tmp["domain"               ] = domain
		tmp["domain_extended"      ] = get_all_domains(tmp["scheme"], tmp["domain_no_port"], tmp["port"])
		tmp["scheme_domain"        ] = ("{0}://{1}").format(tmp["scheme"], tmp["domain"])
		tmp["scheme_domain_no_port"] = ("{0}://{1}").format(tmp["scheme"], tmp["domain_no_port"])
		# --------------------------------
		tmp["ip_no_port"           ] = None
		tmp["ip"                   ] = None
		tmp["ip_extended"          ] = None
		tmp["scheme_ip"            ] = None
		tmp["scheme_ip_no_port"    ] = None
		# --------------------------------
		tmp["path"                 ] = path
		tmp["query"                ] = query
		tmp["fragment"             ] = fragment
		tmp["path_full"            ] = tmp["path"] + tmp["query"]["full"] + tmp["fragment"]["full"]
		# --------------------------------
		tmp["urls"               ] = {
			"base"  : tmp["scheme_domain"] + tmp["path_full"],
			"domain": {
				"https": get_base_https_url(tmp["scheme"], tmp["domain_no_port"], tmp["port"], tmp["path_full"]),
				"http" : get_base_http_url(tmp["scheme"], tmp["domain_no_port"], tmp["port"], tmp["path_full"])
			},
			"ip"    : {
				"https": None,
				"http" : None
			}
		}
		# --------------------------------
		tmp["relative_paths"     ] = extend_path(tmp["path"]) + extend_path(tmp["path"], tmp["query"]["full"], tmp["fragment"]["full"])
		tmp["absolute_paths"     ] = append_paths(tmp["scheme_domain_no_port"], tmp["relative_paths"]) + append_paths(tmp["scheme_domain"], tmp["relative_paths"])
		# --------------------------------
		for key in tmp:
			if isinstance(tmp[key], list):
				tmp[key] = unique(tmp[key])
		return tmp

	def __set_ip(self, obj):
		try:
			obj["ip_no_port"       ] = socket.gethostbyname(obj["domain_no_port"])
			obj["ip"               ] = ("{0}:{1}").format(obj["ip_no_port"], obj["port"])
			obj["ip_extended"      ] = get_all_domains(obj["scheme"], obj["ip_no_port"], obj["port"])
			obj["scheme_ip"        ] = ("{0}://{1}").format(obj["scheme"], obj["ip"])
			obj["scheme_ip_no_port"] = ("{0}://{1}").format(obj["scheme"], obj["ip_no_port"])
			obj["urls"]["ip"       ] = {
				"https": get_base_https_url(obj["scheme"], obj["ip_no_port"], obj["port"], obj["path_full"]),
				"http" : get_base_http_url(obj["scheme"], obj["ip_no_port"], obj["port"], obj["path_full"])
			}
		except socket.error as ex:
			self.__print_debug(ex)
		return obj

	# ------------------------------------

	def __remove_content_length(self, content_length):
		self.__content_lengths.pop(self.__content_lengths.index(content_length))

	def __add_content_length(self, content_length):
		self.__content_lengths = unique(self.__content_lengths + [content_length])

	def get_results(self):
		return self.__collection

	def __print_error(self, text):
		self.__error = True
		print_red(("ERROR: {0}").format(text))

	def __print_debug(self, error, text = ""):
		if self.__debug:
			with self.__print_lock:
				if text:
					print_yellow(text)
				print_cyan(error)

	def __encode(self, values):
		encoding = "UTF-8"
		if isinstance(values, list):
			return [value.encode(encoding) for value in values]
		else:
			return values.encode(encoding)

	def __decode(self, values):
		if isinstance(values, list):
			tmp = []
			error = ""
			for value in values:
				(decoded, error) = decode(value)
				if error:
					break
				tmp.append(decoded)
			return (tmp, error)
		else:
			return decode(values)

	# ------------------------------------

	def run(self, dump = False):
		self.__validate_inaccessible_url()
		if self.__error:
			return
		self.__fetch_inaccessible_ip()
		if self.__error:
			return
		# self.__set_allowed_http_methods() # NOTE: Not needed at the moment.
		self.__prepare_collection()
		if not self.__collection:
			print("No test records were created")
			return
		print_cyan(("Number of created test records: {0}").format(len(self.__collection)))
		if dump:
			self.__remove_duplicates()
			print_time("Dumping the test records in the output file...")
			self.__collection = pop(self.__collection, self.__exclude_from_dump)
			return
		self.__run_tests()
		self.__validate_results()

	def __validate_inaccessible_url(self):
		print_cyan(("Normalized inaccessible URL: {0}").format(self.__url["urls"]["base"]))
		print_time(("Validating the inaccessible URL using HTTP {0} method...").format(self.__force if self.__force else self.__default_method))
		record = self.__fetch(url = self.__url["urls"]["base"], method = self.__force if self.__force else self.__default_method, ignore = False)
		if record["code"] <= 0:
			self.__print_error("Cannot validate the inaccessible URL, script will exit shortly...")
		elif "base" in self.__content_lengths:
			print_green(("Ignoring the inaccessible URL response content length: {0}").format(record["length"]))
			self.__remove_content_length("base")
			self.__add_content_length(record["length"])

	def __fetch_inaccessible_ip(self):
		print_time("Fetching the IP of inaccessible URL...")
		self.__set_ip(self.__url)
		if not self.__url["ip_no_port"]:
			self.__print_error("Cannot fetch the IP of inaccessible URL, script will exit shortly...")

	def __set_allowed_http_methods(self):
		if self.__force:
			print_cyan(("Forcing HTTP {0} method for all non-specific test cases...").format(self.__force))
			self.__allowed_methods = [self.__force]
		else:
			print_time("Fetching allowed HTTP methods...")
			record = self.__fetch(url = self.__url["urls"]["base"], method = "OPTIONS", ignore = False, response_headers = True)
			if record["code"] > 0:
				if record["curl"]:
					methods = re.search(r"(?<=^allow\:).+", record["response_headers"], self.__regex_flags) # NOTE: HTTP response headers are returned in plaintext.
					if methods:
						for method in methods[0].split(","):
							method = method.strip().upper()
							if method not in self.__allowed_methods:
								self.__allowed_methods.append(method)
				else:
					for key in record["response_headers"]: # NOTE: HTTP response headers are returned as dictionary.
						if key.lower() == "allow":
							for method in record["response_headers"][key].split(","):
								method = method.strip().upper()
								if method not in self.__allowed_methods:
									self.__allowed_methods.append(method)
							break
			if not self.__allowed_methods:
				print_cyan(("Cannot fetch allowed HTTP methods, using default built-in HTTP {0} method...").format(self.__default_method))
				self.__allowed_methods = [self.__default_method]
			else:
				print_green(("Allowed HTTP methods: [{0}]").format((", ").join(self.__allowed_methods)))

	# ------------------------------------

	def __fetch(self, url, method = None, headers = None, cookies = None, body = None, user_agent = None, proxy = None, curl = None, ignore = True, response_headers = False, response_body = False, save = False):
		record = self.__record("SYSTEM-0", url, method, headers, cookies, body, user_agent, proxy, curl)
		return self.__send_curl(record, ignore, response_headers, response_body, save) if record["curl"] else self.__send_request(record, ignore, response_headers, response_body, save)

	def __records(self, identifier, urls, methods = None, headers = None, cookies = None, body = None, user_agent = None, proxy = None, curl = None, repeat = None):
		if not isinstance(urls, list):
			urls = [urls]
		if not isinstance(methods, list):
			methods = [methods]
		if not repeat:
			repeat = self.__repeat
		if headers:
			for url in urls:
				for method in methods:
					for header in headers:
						if not isinstance(header, list):
							# NOTE: PycURL accepts only string arrays as HTTP request headers.
							header = [header]
						for i in range(repeat):
							self.__collection.append(self.__record(identifier, url, method, header, cookies, body, user_agent, proxy, curl))
		else:
			for url in urls:
				for method in methods:
					for i in range(repeat):
						self.__collection.append(self.__record(identifier, url, method, [], cookies, body, user_agent, proxy, curl))

	def __record(self, identifier, url, method, headers, cookies, body, user_agent, proxy, curl):
		self.__identifier += 1
		# identifier = ("{0}-{1}").format(self.__identifier, identifier)
		if not method:
			method = self.__force if self.__force else self.__default_method
		headers = self.__inspect_headers(headers)
		cookies = self.__inspect_cookies(cookies)
		if not user_agent:
			user_agent = self.__get_user_agent()
		if not proxy:
			proxy = self.__proxy
		if not isinstance(curl, bool):
			curl = self.__curl
		record = {
			"raw"             : self.__identifier,
			"id"              : identifier,
			"url"             : url,
			"method"          : method,
			"headers"         : headers,
			"cookies"         : cookies,
			"body"            : body,
			"user_agent"      : user_agent,
			"proxy"           : proxy,
			"command"         : None,
			"code"            : ERROR,
			"length"          : 0,
			"response"        : None,
			"response_headers": None,
			"curl"            : curl
		}
		record["command"] = self.__build_command(record)
		return record

	def __inspect_headers(self, headers = None):
		tmp = []
		exists = set()
		if headers:
			for header in headers:
				key, value = get_header_key_value(header)
				if key:
					exists.add(key.lower())
					tmp.append(format_header_key_value(key, value))
		for header in self.__headers:
			key, value = get_header_key_value(header)
			if key and key.lower() not in exists: # NOTE: Extra HTTP request headers cannot override test HTTP request headers.
				tmp.append(format_header_key_value(key, value))
		return tmp

	def __inspect_cookies(self, cookies = None):
		tmp = []
		exists = set()
		if cookies:
			for cookie in cookies:
				key, value = get_cookie_key_value(cookie)
				if key:
					exists.add(key.lower())
					tmp.append(format_cookie_key_value(key, value))
		for cookie in self.__cookies:
			key, value = get_cookie_key_value(cookie)
			if key and key.lower() not in exists: # NOTE: Extra HTTP cookies cannot override test HTTP cookies.
				tmp.append(format_cookie_key_value(key, value))
		return tmp

	def __get_user_agent(self):
		return self.__user_agents[random.randint(0, self.__user_agents_len - 1)] if self.__user_agents_len > 1 else self.__user_agents[0]

	def __build_command(self, record):
		tmp = ["curl", ("--connect-timeout {0}").format(self.__connect_timeout), ("-m {0}").format(self.__read_timeout), "-iskL", ("--max-redirs {0}").format(self.__max_redirects), "--path-as-is"]
		if record["body"]:
			tmp.append(set_param(record["body"], "-d"))
		if record["proxy"]:
			tmp.append(set_param(record["proxy"], "-x"))
		if record["user_agent"]:
			tmp.append(set_param(record["user_agent"], "-A"))
		if record["headers"]:
			for header in record["headers"]:
				tmp.append(set_param(header, "-H"))
		if record["cookies"]:
			tmp.append(set_param(("; ").join(record["cookies"]), "-b"))
		tmp.append(set_param(record["method"], "-X"))
		tmp.append(set_param(record["url"]))
		tmp = (" ").join(tmp)
		return tmp

	# ------------------------------------

	def __remove_duplicates(self):
		tmp = []
		exists = set()
		for record in self.__collection:
			command = re.sub((" -A \\{0}.+?\\{0} ").format(default_quotes), " ", record["command"])
			if command not in exists and not exists.add(command):
				tmp.append(record)
		self.__collection = tmp

	def __run_tests(self):
		results = []
		print_time(("Running tests with {0} engine...").format("PycURL" if self.__curl else "Python Requests"))
		print("Press CTRL + C to exit early - results will be saved")
		with alive_progress.alive_bar(len(self.__collection), title = "Progress:") as bar:
			with concurrent.futures.ThreadPoolExecutor(max_workers = self.__threads) as executor:
				subprocesses = []
				try:
					for record in self.__collection:
						subprocesses.append(executor.submit(self.__send_curl if record["curl"] else self.__send_request, record))
					for subprocess in concurrent.futures.as_completed(subprocesses):
						results.append(subprocess.result())
						bar()
				except KeyboardInterrupt:
					executor.shutdown(wait = True, cancel_futures = True)
		self.__collection = results

	# ------------------------------------

	def __send_curl(self, record, ignore = True, response_headers = False, response_body = False, save = True):
		curl = None
		cookiefile = None
		headers = None
		response = None
		try:
			# ----------------------------
			curl = pycurl.Curl()
			# ----------------------------
			cookiefile = tempfile.NamedTemporaryFile(mode = "r") # NOTE: Important! Store and pass HTTP cookies on HTTP redirects.
			curl.setopt(pycurl.COOKIESESSION, True)
			curl.setopt(pycurl.COOKIEFILE, cookiefile.name)
			curl.setopt(pycurl.COOKIEJAR, cookiefile.name)
			# ----------------------------
			if response_headers:
				headers = io.BytesIO()
				curl.setopt(pycurl.HEADERFUNCTION, headers.write)
			# ----------------------------
			response = io.BytesIO()
			curl.setopt(pycurl.WRITEFUNCTION, response.write)
			# ----------------------------
			curl.setopt(pycurl.HTTP_VERSION, pycurl.CURL_HTTP_VERSION_1_1)
			curl.setopt(pycurl.VERBOSE, False)
			curl.setopt(pycurl.PATH_AS_IS, True)
			curl.setopt(pycurl.SSL_VERIFYHOST, self.__verify)
			curl.setopt(pycurl.SSL_VERIFYPEER, self.__verify)
			curl.setopt(pycurl.PROXY_SSL_VERIFYHOST, self.__verify)
			curl.setopt(pycurl.PROXY_SSL_VERIFYPEER, self.__verify)
			curl.setopt(pycurl.FOLLOWLOCATION, self.__allow_redirects)
			curl.setopt(pycurl.MAXREDIRS, self.__max_redirects)
			curl.setopt(pycurl.CONNECTTIMEOUT, self.__connect_timeout)
			curl.setopt(pycurl.TIMEOUT, self.__read_timeout)
			# ----------------------------
			# NOTE: Important! Encode Unicode characters.
			curl.setopt(pycurl.URL, record["url"])
			curl.setopt(pycurl.CUSTOMREQUEST, record["method"])
			if record["method"] in ["HEAD"]:
				curl.setopt(pycurl.NOBODY, True)
			if record["user_agent"]:
				curl.setopt(pycurl.USERAGENT, self.__encode(record["user_agent"]))
			if record["headers"]:
				curl.setopt(pycurl.HTTPHEADER, self.__encode(record["headers"])) # Will override 'User-Agent' HTTP request header.
			if record["cookies"]:
				curl.setopt(pycurl.COOKIE, ("; ").join(record["cookies"]))
			if record["body"]:
				curl.setopt(pycurl.POSTFIELDS, record["body"])
			if record["proxy"]:
				curl.setopt(pycurl.PROXY, record["proxy"])
			# ----------------------------
			curl.perform()
			# ----------------------------
			record["code"] = int(curl.getinfo(pycurl.RESPONSE_CODE))
			record["length"] = int(curl.getinfo(pycurl.SIZE_DOWNLOAD))
			record["id"] = ("{0}-{1}-{2}").format(record["code"], record["length"], record["id"])
			(record["response"], error) = self.__decode(response.getvalue())
			if error:
				record["code"] = ERROR
				self.__print_debug(error, ("{0}: {1}").format(record["id"], record["command"]))
			else:
				if response_headers:
					(record["response_headers"], error) = self.__decode(headers.getvalue())
					if error:
						record["code"] = ERROR
						self.__print_debug(error, ("{0}: {1}").format(record["id"], record["command"]))
				if ignore:
					if record["length"] in self.__content_lengths or (self.__ignore_regex and re.search(self.__ignore_regex, record["response"], self.__regex_flags)):
						record["code"] = IGNORED
				if save and record["code"] >= 200 and record["code"] < 400: # NOTE: Additional validation to prevent congestion from writing large and usless data to files.
					file = os.path.join(self.__directory, ("{0}.txt").format(record["id"]))
					if not os.path.exists(file):
						open(file, "w").write(record["response"])
			if not response_body:
				record["response"] = ""
			# ----------------------------
		except (UnicodeEncodeError, pycurl.error, OSError, FileNotFoundError) as ex:
			# ----------------------------
			self.__print_debug(ex, ("{0}: {1}").format(record["id"], record["command"]))
			# ----------------------------
		finally:
			# ----------------------------
			if response:
				response.close()
			# ----------------------------
			if headers:
				headers.close()
			# ----------------------------
			if curl:
				curl.close()
			# ----------------------------
			if cookiefile:
				cookiefile.close() # NOTE: Important! Close the file handle strictly after closing the cURL handle.
			# ----------------------------
		return record

	def __send_request(self, record, ignore = True, response_headers = False, response_body = False, save = True):
		session = None
		response = None
		try:
			# ----------------------------
			session = requests.Session()
			session.max_redirects = self.__max_redirects
			# ----------------------------
			session.cookies.clear()
			# ----------------------------
			request = requests.Request(
				record["method"],
				record["url"]
			)
			if record["user_agent"]:
				request.headers["User-Agent"] = self.__encode(record["user_agent"])
			if record["headers"]:
				self.__set_double_headers(request, record["headers"]) # Will override 'User-Agent' HTTP request header.
			if record["cookies"]:
				session.cookies.update(array_to_dict(record["cookies"], separator = "="))
			if record["body"]:
				request.data = record["body"]
			if record["proxy"]:
				session.proxies["https"] = session.proxies["http"] = record["proxy"]
			# ----------------------------
			prepared = session.prepare_request(request)
			prepared.url = record["url"]
			# ----------------------------
			response = session.send(
				prepared,
				verify = self.__verify,
				allow_redirects = self.__allow_redirects,
				timeout = (self.__connect_timeout, self.__read_timeout)
			)
			# ----------------------------
			record["code"] = int(response.status_code)
			record["length"] = len(response.content)
			record["id"] = ("{0}-{1}-{2}").format(record["code"], record["length"], record["id"])
			(record["response"], error) = self.__decode(response.content)
			if error:
				record["code"] = ERROR
				self.__print_debug(error, ("{0}: {1}").format(record["id"], record["command"]))
			else:
				if response_headers:
					record["response_headers"] = dict(response.headers)
				if ignore:
					if record["length"] in self.__content_lengths or (self.__ignore_regex and re.search(self.__ignore_regex, record["response"], self.__regex_flags)):
						record["code"] = IGNORED
				if save and record["code"] >= 200 and record["code"] < 400: # NOTE: Additional validation to prevent congestion from writing large and usless data to files.
					file = os.path.join(self.__directory, ("{0}.txt").format(record["id"]))
					if not os.path.exists(file):
						open(file, "w").write(record["response"])
			if not response_body:
				record["response"] = ""
			# ----------------------------
		except (UnicodeEncodeError, requests.packages.urllib3.exceptions.LocationParseError, requests.exceptions.RequestException, FileNotFoundError) as ex:
			# ----------------------------
			self.__print_debug(ex, ("{0}: {1}").format(record["id"], record["command"]))
			# ----------------------------
		finally:
			# ----------------------------
			if response:
				response.close()
			# ----------------------------
			if session:
				session.close()
			# ----------------------------
		return record

	def __set_double_headers(self, request, headers):
		exists = set()
		for header in headers:
			key, value = get_header_key_value(header)
			request.headers[key if key not in exists and not exists.add(key) else uniquestr(key)] = self.__encode(value)

	# ------------------------------------

	def __validate_results(self):
		print_time("Validating results...")
		self.__mark_duplicates()
		output = Output(self.__collection, self.__exclude_from_results, self.__status_codes, self.__show_table)
		self.__collection = output.show_results()
		if len(self.__collection) < 1:
			print_time("All results are ignored")
		output.show_stats_table()

	def __mark_duplicates(self):
		exists = set()
		for record in self.__collection:
			if record["id"] not in exists and not exists.add(record["id"]):
				continue
			record["code"] = DUPLICATE

	# ------------------------------------

	def __prepare_collection(self):
		print_time("Preparing test records...")
		# --------------------------------
		# NOTE: Stress testing.
		self.__records(
			identifier = "STRESS-1",
			urls       = self.__url["urls"]["base"]
		)

# ----------------------------------------

class Output:

	def __init__(self, collection, exclude_from_results, status_codes, show_table):
		self.__collection   = pop(sorted([record for record in collection if record["code"] >= 100 and record["code"] < 600], key = lambda record: (record["code"], -record["length"], record["raw"])), exclude_from_results) # filtered
		self.__stats        = self.__count(collection) # unfiltered
		self.__status_codes = status_codes
		self.__show_table   = show_table

	def __count(self, collection):
		tmp = {}
		for record in collection:
			if record["code"] not in tmp:
				tmp[record["code"]] = 0
			tmp[record["code"]] += 1
		return dict(sorted(tmp.items()))

	def __check_status_codes(self, array):
		return any(test in array for test in self.__status_codes)

	# ------------------------------------

	def __color(self, value, color):
		return ("{0}{1}{2}").format(color, value, colorama.Style.RESET_ALL)

	def __results_row(self, record, color):
		return [self.__color(record[key], color) for key in ["id", "code", "length", "command"]]

	def __show_results_table(self):
		tmp = []; table = []
		for record in self.__collection:
			if record["code"] < 100 or record["code"] >= 600:
				continue
			elif record["code"] >= 500:
				if self.__check_status_codes(["5xx", "all"]):
					table.append(self.__results_row(record, colorama.Fore.CYAN))
					tmp.append(record)
			elif record["code"] >= 400:
				if self.__check_status_codes(["4xx", "all"]):
					table.append(self.__results_row(record, colorama.Fore.RED))
					tmp.append(record)
			elif record["code"] >= 300:
				if self.__check_status_codes(["3xx", "all"]):
					table.append(self.__results_row(record, colorama.Fore.YELLOW))
					tmp.append(record)
			elif record["code"] >= 200:
				if self.__check_status_codes(["2xx", "all"]):
					table.append(self.__results_row(record, colorama.Fore.GREEN))
					tmp.append(record)
			elif record["code"] >= 100:
				if self.__check_status_codes(["1xx", "all"]):
					table.append(self.__results_row(record, colorama.Fore.WHITE))
					tmp.append(record)
		if table:
			print(tabulate.tabulate(table, tablefmt = "plain", colalign = ("right", "right", "right", "left")))
		return tmp

	# ------------------------------------

	def __show_results_json(self):
		tmp = []
		for record in self.__collection:
			if record["code"] < 100 or record["code"] >= 600:
				continue
			elif record["code"] >= 500:
				if self.__check_status_codes(["5xx", "all"]):
					print_cyan(jdump(record))
					tmp.append(record)
			elif record["code"] >= 400:
				if self.__check_status_codes(["4xx", "all"]):
					print_red(jdump(record))
					tmp.append(record)
			elif record["code"] >= 300:
				if self.__check_status_codes(["3xx", "all"]):
					print_yellow(jdump(record))
					tmp.append(record)
			elif record["code"] >= 200:
				if self.__check_status_codes(["2xx", "all"]):
					print_green(jdump(record))
					tmp.append(record)
			elif record["code"] >= 100:
				if self.__check_status_codes(["1xx", "all"]):
					print_white(jdump(record))
					tmp.append(record)
		return tmp

	# ------------------------------------

	def __stats_row(self, code, count, color):
		return [self.__color(entry, color) for entry in [code, count]]

	def show_stats_table(self):
		table = []; table_special = []
		for code, count in self.__stats.items():
			if code == ERROR:
				table_special.append(self.__stats_row("Errors", count, colorama.Fore.WHITE))
			elif code == IGNORED:
				table_special.append(self.__stats_row("Ignored", count, colorama.Fore.WHITE))
			elif code < 100 or code >= 600:
				continue
			elif code >= 500:
				table.append(self.__stats_row(code, count, colorama.Fore.CYAN))
			elif code >= 400:
				table.append(self.__stats_row(code, count, colorama.Fore.RED))
			elif code >= 300:
				table.append(self.__stats_row(code, count, colorama.Fore.YELLOW))
			elif code >= 200:
				table.append(self.__stats_row(code, count, colorama.Fore.GREEN))
			elif code >= 100:
				table.append(self.__stats_row(code, count, colorama.Fore.WHITE))
		if table or table_special:
			print(tabulate.tabulate(table + table_special, ["Status Code", "Count"], tablefmt = "outline", colalign = ("left", "right")))

	# ------------------------------------

	def show_results(self):
		return self.__show_results_table() if self.__show_table else self.__show_results_json()

# ----------------------------------------

class MyArgParser(argparse.ArgumentParser):

	def print_help(self):
		print("Stresser v12.3 ( github.com/ivan-sincek/forbidden )")
		print("")
		print("Usage:   stresser -u url                        -dir directory -r repeat -th threads [-f force] [-o out         ]")
		print("Example: stresser -u https://example.com/secret -dir results   -r 1000   -th 200     [-f GET  ] [-o results.json]")
		print("")
		print("DESCRIPTION")
		print("    Bypass 4xx HTTP response status codes with stress testing")
		print("URL")
		print("    Inaccessible URL")
		print("    -u, --url = https://example.com/admin | etc.")
		print("IGNORE QUERY STRING AND FRAGMENT")
		print("    Ignore URL query string and fragment")
		print("    -iqsf, --ignore-query-string-and-fragment")
		print("IGNORE PYTHON REQUESTS")
		print("    Use PycURL instead of the default Python Requests where applicable")
		print("    PycURL might throw OSError if large number of threads is used due to opening too many session cookie files at once")
		print("    -ir, --ignore-requests")
		print("FORCE")
		print("    Force an HTTP method for all non-specific test cases")
		print("    -f, --force = GET | POST | CUSTOM | etc.")
		print("HEADER")
		print("    Specify any number of extra HTTP request headers")
		print("    Extra HTTP request headers will not override test's HTTP request headers")
		print("    Semi-colon in e.g., 'Content-Type;' will expand to an empty HTTP request header")
		print("    -H, --header = \"Authorization: Bearer ey...\" | Content-Type; | etc.")
		print("COOKIE")
		print("    Specify any number of extra HTTP cookies")
		print("    Extra HTTP cookies will not override test's HTTTP cookies")
		print("    -b, --cookie = PHPSESSIONID=3301 | etc.")
		print("IGNORE")
		print("    Filter out 200 OK false positive results with RegEx")
		print("    Spacing will be stripped")
		print("    -i, --ignore = Inaccessible | \"Access Denied\" | etc.")
		print("CONTENT LENGTHS")
		print("    Filter out 200 OK false positive results by HTTP response content lengths")
		print("    Specify 'base' to ignore content length of the base HTTP response")
		print("    Use comma-separated values")
		print("    -l, --content-lengths = 12 | base | etc.")
		print("REQUEST TIMEOUT")
		print("    Request timeout")
		print("    Default: 60")
		print("    -rt, --request-timeout = 30 | etc.")
		print("REPEAT")
		print("    Number of total HTTP requests to send for each test case")
		print("    -r, --repeat = 1000 | etc.")
		print("THREADS")
		print("    Number of parallel threads to run")
		print("    -th, --threads = 20 | etc.")
		print("USER AGENT")
		print("    User agent to use")
		print(("    Default: {0}").format(default_user_agent))
		print("    -a, --user-agent = curl/3.30.1 | random[-all] | etc.")
		print("PROXY")
		print("    Web proxy to use")
		print("    -x, --proxy = http://127.0.0.1:8080 | etc.")
		print("HTTP RESPONSE STATUS CODES")
		print("    Include only specific HTTP response status codes in the results")
		print("    Use comma-separated values")
		print("    Default: 2xx | 3xx")
		print("    -sc, --status-codes = 1xx | 2xx | 3xx | 4xx | 5xx | all")
		print("SHOW TABLE")
		print("    Display the results in a table instead of JSON")
		print("    Intended for a wide screen use")
		print("    -st, --show-table")
		print("OUT")
		print("    Output file")
		print("    -o, --out = results.json | etc.")
		print("DIRECTORY")
		print("    Output directory")
		print("    All valid and unique HTTP responses will be saved in this directory")
		print("    -dir, --directory = results | etc.")
		print("DUMP")
		print("    Dump all the tests in the output file without running them")
		print("    -dmp, --dump")
		print("DEBUG")
		print("    Debug output")
		print("    -dbg, --debug")

	def error(self, message):
		if len(sys.argv) > 1:
			print("Missing a mandatory option (-u, -dir, -r, -th) and/or optional (-iqsf, -ir, -f, -H, -b, -i, -l, -rt, -a, -x, -sc, -st, -o, -dmp, -dbg)")
			print("Use -h or --help for more info")
		else:
			self.print_help()
		exit()

class Validate:

	def __init__(self):
		self.__proceed = True
		self.__parser  = MyArgParser()
		self.__parser.add_argument("-u"   , "--url"                             , required = True , type   = str         , default = ""   )
		self.__parser.add_argument("-iqsf", "--ignore-query-string-and-fragment", required = False, action = "store_true", default = False)
		self.__parser.add_argument("-ir"  , "--ignore-requests"                 , required = False, action = "store_true", default = False)
		self.__parser.add_argument("-f"   , "--force"                           , required = False, type   = str.upper   , default = ""   )
		self.__parser.add_argument("-H"   , "--header"                          , required = False, action = "append"    , nargs   = "+"  )
		self.__parser.add_argument("-b"   , "--cookie"                          , required = False, action = "append"    , nargs   = "+"  )
		self.__parser.add_argument("-i"   , "--ignore"                          , required = False, type   = str         , default = ""   )
		self.__parser.add_argument("-l"   , "--content-lengths"                 , required = False, type   = str.lower   , default = ""   )
		self.__parser.add_argument("-rt"  , "--request-timeout"                 , required = False, type   = str         , default = ""   )
		self.__parser.add_argument("-r"   , "--repeat"                          , required = True , type   = str         , default = ""   )
		self.__parser.add_argument("-th"  , "--threads"                         , required = True , type   = str         , default = ""   )
		self.__parser.add_argument("-a"   , "--user-agent"                      , required = False, type   = str         , default = ""   )
		self.__parser.add_argument("-x"   , "--proxy"                           , required = False, type   = str         , default = ""   )
		self.__parser.add_argument("-sc"  , "--status-codes"                    , required = False, type   = str.lower   , default = ""   )
		self.__parser.add_argument("-st"  , "--show-table"                      , required = False, action = "store_true", default = False)
		self.__parser.add_argument("-o"   , "--out"                             , required = False, type   = str         , default = ""   )
		self.__parser.add_argument("-dir" , "--directory"                       , required = True , type   = str         , default = ""   )
		self.__parser.add_argument("-dmp" , "--dump"                            , required = False, action = "store_true", default = False)
		self.__parser.add_argument("-dbg" , "--debug"                           , required = False, action = "store_true", default = False)

	def run(self):
		self.__args                 = self.__parser.parse_args()
		self.__args.url             = self.__parse_url(self.__args.url, "url")                  # required
		self.__args.header          = self.__parse_header(self.__args.header)                   if self.__args.header          else []
		self.__args.cookie          = self.__parse_cookie(self.__args.cookie)                   if self.__args.cookie          else []
		self.__args.ignore          = self.__parse_ignore(self.__args.ignore)                   if self.__args.ignore          else ""
		self.__args.content_lengths = self.__parse_content_lengths(self.__args.content_lengths) if self.__args.content_lengths else []
		self.__args.request_timeout = self.__parse_request_timeout(self.__args.request_timeout) if self.__args.request_timeout else 60
		self.__args.repeat          = self.__parse_repeat(self.__args.repeat)                   # required
		self.__args.threads         = self.__parse_threads(self.__args.threads)                 # required
		self.__args.user_agent      = self.__parse_user_agent(self.__args.user_agent)           if self.__args.user_agent      else [default_user_agent]
		self.__args.proxy           = self.__parse_url(self.__args.proxy, "proxy")              if self.__args.proxy           else ""
		self.__args.status_codes    = self.__parse_status_codes(self.__args.status_codes)       if self.__args.status_codes    else ["2xx", "3xx"]
		self.__args.directory       = self.__parse_directory(self.__args.directory)             # required
		self.__args                 = vars(self.__args)
		return self.__proceed

	def get_arg(self, key):
		return self.__args[key]

	def __error(self, msg):
		self.__proceed = False
		self.print_error(msg)

	def print_error(self, msg):
		print(("ERROR: {0}").format(msg))

	def __parse_url(self, value, key):
		data = {
			"url": {
				"schemes"     : ["http", "https"],
				"scheme_error": {
					"required"   : "Inaccessible URL: Scheme is required",
					"unsupported": "Inaccessible URL: Supported schemes are 'http' and 'https'"
				},
				"domain_error": "Inaccessible URL: Invalid domain name",
				"port_error"  : "Inaccessible URL: Port number is out of range"
			},
			"proxy": {
				"schemes"     : ["http", "https", "socks4", "socks4h", "socks5", "socks5h"],
				"scheme_error": {
					"required"   : "Proxy URL: Scheme is required",
					"unsupported": "Proxy URL: Supported schemes are 'http[s]', 'socks4[h]', and 'socks5[h]'"
				},
				"domain_error": "Proxy URL: Invalid domain name",
				"port_error"  : "Proxy URL: Port number is out of range"
			}
		}
		tmp = urllib.parse.urlsplit(value)
		if not tmp.scheme:
			self.__error(data[key]["scheme_error"]["required"])
		elif tmp.scheme not in data[key]["schemes"]:
			self.__error(data[key]["scheme_error"]["unsupported"])
		elif not tmp.netloc:
			self.__error(data[key]["domain_error"])
		elif tmp.port and (tmp.port < 1 or tmp.port > 65535):
			self.__error(data[key]["port_error"])
		return value

	def __parse_header(self, headers):
		tmp = []
		for header in headers:
			header = header[0]
			key, value = get_header_key_value(header)
			if not key:
				self.__error(("Invalid header: {0}").format(header))
				continue
			tmp.append(format_header_key_value(key, value))
		return tmp

	def __parse_cookie(self, cookies):
		tmp = []
		for cookie in cookies:
			cookie = cookie[0]
			key, value = get_cookie_key_value(cookie)
			if not key:
				self.__error(("Invalid cookie: {0}").format(cookie))
				continue
			tmp.append(format_cookie_key_value(key, value))
		return tmp

	def __parse_ignore(self, value):
		try:
			re.compile(value)
		except re.error:
			self.__error(("Invalid RegEx: {0}").format(value))
		return value

	def __parse_content_lengths(self, value):
		tmp = []
		for entry in value.lower().split(","):
			entry = entry.strip()
			if not entry:
				continue
			elif entry in ["base"]:
				tmp.append(entry)
			elif not entry.isdigit() or int(entry) < 0:
				self.__error("Content lengths must be either 'base' or numeric greater than or equal to zero")
				break
			else:
				tmp.append(int(entry))
		return unique(tmp)

	def __parse_request_timeout(self, value):
		if not value.isdigit():
			self.__error("Request timeout must be numeric")
		else:
			value = int(value)
			if value <= 0:
				self.__error("Request timeout must be greater than zero")
		return value

	def __parse_repeat(self, value):
		if not value.isdigit():
			self.__error("Number of total HTTP requests to send must be numeric")
		else:
			value = int(value)
			if value <= 0:
				self.__error("Number of total HTTP requests to send must be greater than zero")
		return value

	def __parse_threads(self, value):
		if not value.isdigit():
			self.__error("Number of parallel threads to run must be numeric")
		else:
			value = int(value)
			if value <= 0:
				self.__error("Number of parallel threads to run must be greater than zero")
		return value

	def __parse_user_agent(self, value):
		lower = value.lower()
		if lower == "random-all":
			return get_all_user_agents()
		elif lower == "random":
			return [get_random_user_agent()]
		else:
			return [value]

	def __parse_status_codes(self, value):
		tmp = []
		for entry in value.lower().split(","):
			entry = entry.strip()
			if not entry:
				continue
			elif entry not in ["1xx", "2xx", "3xx", "4xx", "5xx", "all"]:
				self.__error("Supported HTTP response status codes are '1xx', '2xx', '3xx', '4xx', '5xx', or 'all'")
				break
			elif entry == "all":
				tmp = [entry]
				break
			else:
				tmp.append(entry)
		return unique(tmp)

	def __parse_directory(self, value):
		if not os.path.isdir(value):
			self.__error("Output directory does not exists or is not a directory")
		return value

# ----------------------------------------

def main():
	validate = Validate()
	if validate.run():
		print("##########################################################################")
		print("#                                                                        #")
		print("#                             Stresser v12.3                             #")
		print("#                                 by Ivan Sincek                         #")
		print("#                                                                        #")
		print("# Bypass 4xx HTTP response status codes  with stress testing.            #")
		print("# GitHub repository at github.com/ivan-sincek/forbidden.                 #")
		print("# Feel free to donate ETH at 0xbc00e800f29524AD8b0968CEBEAD4cD5C5c1f105. #")
		print("#                                                                        #")
		print("##########################################################################")
		out = validate.get_arg("out")
		dump = validate.get_arg("dump")
		stresser = Stresser(
			validate.get_arg("url"),
			validate.get_arg("ignore_query_string_and_fragment"),
			validate.get_arg("ignore_requests"),
			validate.get_arg("force"),
			validate.get_arg("header"),
			validate.get_arg("cookie"),
			validate.get_arg("ignore"),
			validate.get_arg("content_lengths"),
			validate.get_arg("request_timeout"),
			validate.get_arg("repeat"),
			validate.get_arg("threads"),
			validate.get_arg("user_agent"),
			validate.get_arg("proxy"),
			validate.get_arg("status_codes"),
			validate.get_arg("show_table"),
			validate.get_arg("directory"),
			validate.get_arg("debug")
		)
		stresser.run(dump)
		results = stresser.get_results()
		if dump and not out:
			validate.print_error("Output file not found")
		stopwatch.stop()
		if results and out:
			write_file(jdump(results), out)

if __name__ == "__main__":
	main()
