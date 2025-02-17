#!/usr/bin/env python3

from .       import array, cookie, encode, general, grep, header, path, report, test, value
from .record import Records
from .url    import URL, Scheme

import alive_progress, concurrent.futures, http.client, io, pycurl, random, requests, ssl, time

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# ----------------------------------------

class Forbidden:

	def __init__(
		self,
		url              : str,
		ignore_parameters: bool,
		ignore_requests  : bool,
		tests            : list[general.Test],
		values           : list[str],
		force            : str,
		paths            : list[str],
		evil             : str,
		headers          : list[str],
		cookies          : list[str],
		ignore_regex     : str,
		content_lengths  : list[int | general.ContentLength],
		request_timeout  : int,
		sleep            : int,
		user_agents      : list[str],
		proxy            : str,
		status_codes     : list[general.StatusCode],
		debug            : bool
	):
		"""
		Class for managing the tool.
		"""
		self.__url                   = URL(url, ignore_parameters)
		self.__tests                 = tests
		self.__values                = values
		self.__force                 = force
		self.__accessible            = path.join_multiple(self.__url.domain.scheme_domain_port, paths)
		self.__accessible_scope      = [general.Test.PATH_OVERRIDES]
		self.__evil                  = URL(evil)
		self.__evil_scope            = [general.Test.HOST_OVERRIDES, general.Test.HEADERS, general.Test.BEARER_AUTHS, general.Test.REDIRECTS, general.Test.PARSERS]
		self.__headers               = headers
		self.__cookies               = cookies
		self.__ignore                = ignore_regex
		self.__content_lengths       = content_lengths
		self.__sleep                 = sleep
		self.__user_agents           = user_agents
		self.__user_agents_len       = len(self.__user_agents)
		self.__proxy                 = proxy
		self.__status_codes          = status_codes
		self.__debug                 = debug
		# --------------------------------
		self.__engine                = general.Engine.PYCURL if ignore_requests else general.Engine.PYTHON_REQUESTS
		self.__verify                = False
		self.__allow_redirects       = True
		self.__max_redirects         = 10
		self.__connect_timeout       = request_timeout
		self.__read_timeout          = request_timeout
		# --------------------------------
		self.__default_method        = "GET"
		self.__main_method           = self.__force or self.__default_method
		self.__allowed_methods       = []
		self.__allowed_methods_scope = [general.Test.METHODS, general.Test.METHOD_OVERRIDES]
		# --------------------------------
		self.__collection            = Records()

	# ------------------------------------

	def __check_scope(self, scope: list[general.Test]):
		"""
		Check if any of the tests are in scope.
		"""
		return any(test in scope for test in self.__tests)

	def __replace_content_length(self, content_length_enum: general.ContentLength, content_length_value: int):
		"""
		Replace a content length enum with a content length value in the content lengths list.
		"""
		self.__content_lengths[self.__content_lengths.index(content_length_enum)] = content_length_value
		self.__content_lengths = list(set(self.__content_lengths))

	def __wait(self):
		"""
		Wait for a period of time.
		"""
		if self.__sleep > 0:
			time.sleep(self.__sleep)

	def __print_debug(self, record: Records.Record):
		"""
		If debugging is enabled, print a test record information and an error message - if any.
		"""
		if self.__debug and record.error:
			general.print_yellow(f"[ DEBUG ] {record.id}: {record.command}")
			general.print_cyan(record.error)

	# ------------------------------------

	def run(self, threads: int, show_table = False, dump = False):
		"""
		Run the tool.
		"""
		results = []
		if self.__validate_inaccessible_url() and self.__validate_evil_url() and self.__validate_accessible_urls():
			self.__fetch_allowed_http_methods()
			self.__prepare_test_records()
			if not self.__collection.len() > 0:
				print("No test records were created")
			else:
				self.__collection.unique()
				general.print_cyan(f"Number of created test records: {self.__collection.len()}")
				if dump:
					print(general.get_timestamp("Dumping the test records in the output file..."))
					results = self.__collection.get_tests()
				else:
					self.__run_tests(threads)
					tmp = report.Report(self.__collection, self.__status_codes)
					results = tmp.show(show_table)
					tmp.show_statistics()
		return results

	def __run_tests(self, threads: int):
		"""
		Run all the tests.
		"""
		print(general.get_timestamp(f"Running tests using the {self.__engine.get_title()} engine..."))
		print("Press CTRL + C to exit early - results will be saved")
		with alive_progress.alive_bar(self.__collection.len(), title = "Progress:") as bar:
			with concurrent.futures.ThreadPoolExecutor(max_workers = threads) as executor:
				subprocesses = []
				try:
					for record in self.__collection.get():
						subprocesses.append(executor.submit(getattr(self, record.engine.get_method()), record))
					for subprocess in concurrent.futures.as_completed(subprocesses):
						record = subprocess.result()
						self.__print_debug(record)
						bar()
				except KeyboardInterrupt:
					executor.shutdown(wait = True, cancel_futures = True)

	# ------------------------------------

	def __validate_inaccessible_url(self):
		"""
		Validate the inaccessible URL.
		"""
		success = True
		general.print_cyan(f"Normalized inaccessible URL: {self.__url.full.initial.domain}")
		if not self.__url.ip.ip:
			general.print_red("Could not fetch the IP address of the inaccessible URL, the tool will now exit...")
			success = False
		else:
			print(general.get_timestamp(f"Validating the inaccessible URL using the HTTP {self.__main_method} method..."))
			record = self.__send(
				url    = self.__url.full.initial.domain,
				method = self.__main_method,
				ignore = False
			)
			if record.status == general.ErrorCode.ERROR.value:
				general.print_red("Inaccessible URL is not valid, the tool will now exit...")
				success = False
			elif general.ContentLength.INITIAL in self.__content_lengths:
				general.print_green(f"Ignoring the inaccessible URL response content length: {record.length}")
				self.__replace_content_length(general.ContentLength.INITIAL, record.length)
		return success

	def __validate_evil_url(self):
		"""
		Validate the evil URL.
		"""
		success = True
		if self.__check_scope(self.__evil_scope):
			general.print_cyan(f"Normalized evil URL: {self.__evil.full.initial.domain}")
			if not self.__evil.ip.ip:
				general.print_red("Could not fetch the IP address of the evil URL, the tool will now exit...")
				success = False
			else:
				print(general.get_timestamp(f"Validating the evil URL using the HTTP {self.__default_method} method..."))
				record = self.__send(
					url    = self.__evil.full.initial.domain,
					method = self.__default_method,
					ignore = True
				)
				if record.status == general.ErrorCode.ERROR.value:
					general.print_red("Evil URL is not valid, the tool will now exit...")
					success = False
				elif record.status == general.ErrorCode.IGNORED.value:
					general.print_red("Evil URL is being ignored, please adjust your options and try again, the tool will now exit...")
					success = False
		return success

	def __validate_accessible_urls(self):
		"""
		Validate the accessible URLs.
		"""
		success = True
		if self.__check_scope(self.__accessible_scope):
			# ----------------------------
			urls = self.__accessible
			length = len(urls)
			self.__accessible = ""
			# ----------------------------
			if length == 1:
				general.print_cyan(f"Normalized accessible URL: {urls[0]}")
				print(general.get_timestamp(f"Validating the accessible URL using the HTTP {self.__default_method} method..."))
				record = self.__send(
					url    = urls[0],
					method = self.__default_method,
					ignore = False
				)
				if record.status == general.ErrorCode.ERROR.value:
					general.print_red("Accessible URL is not valid, the tool will now exit...")
					success = False
				elif record.status >= 200 and record.status < 300:
					self.__accessible = record.url
					if general.ContentLength.PATH in self.__content_lengths:
						general.print_green(f"Ignoring the accessible URL response content length: {record.length}")
						self.__replace_content_length(general.ContentLength.PATH, record.length)
				else:
					general.print_red("Accessible URL did not return 2xx HTTP response status code, the tool will now exit...")
					success = False
			# ----------------------------
			elif length > 1:
				general.print_cyan(f"Using the following built-in accessible URLs:{chr(10)}{(chr(10)).join(urls)}")
				print(general.get_timestamp(f"Validating the built-in accessible URLs using the HTTP {self.__default_method} method..."))
				for url in urls:
					record = self.__send(
						url    = url,
						method = self.__default_method,
						ignore = False
					)
					if record.status >= 200 and record.status < 300:
						general.print_green(f"Accessible URL was found: {record.url}")
						self.__accessible = record.url
						if general.ContentLength.PATH in self.__content_lengths:
							general.print_green(f"Ignoring the accessible URL response content length: {record.length}")
							self.__replace_content_length(general.ContentLength.PATH, record.length)
						break
				if not self.__accessible:
					general.print_yellow("No accessible URL was found, moving on...")
			# ----------------------------
		return success

	def __fetch_allowed_http_methods(self):
		"""
		Fetch the allowed HTTP methods.
		"""
		if self.__force:
			general.print_cyan(f"Forcing the HTTP {self.__main_method} method for all non-specific tests...")
			self.__allowed_methods = [self.__main_method]
		elif self.__check_scope(self.__allowed_methods_scope):
			print(general.get_timestamp(f"Fetching the allowed HTTP methods..."))
			record = self.__send(
				url                   = self.__url.full.initial.domain,
				method                = "OPTIONS",
				ignore                = False,
				keep_response_headers = True
			)
			if record.status > 0:
				value = header.find(record.response_headers, "allow")
				if value:
					for method in value.split(","):
						method = method.strip().upper()
						if method and method not in self.__allowed_methods:
							self.__allowed_methods.append(method)
			if not self.__allowed_methods:
				general.print_yellow(f"Could not fetch the allowed HTTP methods, using the default HTTP {self.__main_method} method instead and moving on...")
				self.__allowed_methods = [self.__main_method]
			else:
				general.print_green(f"Allowed HTTP methods: [{(', ').join(self.__allowed_methods)}]")

	# ------------------------------------

	def __send(self, url: str, method = "", headers: list[str] = [], cookies: list[str] = [], body = "", ignore = True, keep_response_headers = False, keep_response_body = False) -> Records.Record:
		"""
		Send an HTTP request using the default HTTP request engine.\n
		Used for initial validation.
		"""
		record = self.__record("SYSTEM-0", url, method, headers, cookies, body)
		method = getattr(self, record.engine.get_method())
		record = method(record, ignore, keep_response_headers, keep_response_body)
		self.__print_debug(record)
		return record

	# ------------------------------------

	def __records(self, id: str, url: str | list[str], method: str | list[str] = [""], headers: list[str] | list[list[str]] = [[]], cookies: list[str] | list[list[str]] = [[]], body: str | list[str] = [""], engine: general.Engine = None):
		"""
		Create multiple test records and add them to the collection.
		"""
		urls    =  array.to_array(url   )
		methods =  array.to_array(method)
		headers = [array.to_array(header) for header in headers]
		cookies = [array.to_array(cookie) for cookie in cookies]
		bodies  =  array.to_array(body  )
		# --------------------------------
		for __url in urls:
			for __method in methods:
				for __headers in headers:
					for __cookies in cookies:
						for __body in bodies:
							self.__collection.append(self.__record(id, __url, __method, __headers, __cookies, __body, engine))

	def __record(self, id: str, url: str, method = "", headers: list[str] = [], cookies: list[str] = [], body = "", engine: general.Engine = None):
		"""
		Get a test record.
		"""
		return Records.Record(id, url, method or self.__main_method, self.__validate_headers(headers), self.__validate_cookies(cookies), body, self.__get_user_agent(), self.__proxy, engine or self.__engine)

	def __validate_headers(self, headers: list[str] = []) -> list[str]:
		"""
		Add user-supplied HTTP request headers to test-specific HTTP request headers.\n
		Important, user-supplied HTTP request headers cannot override test-specific HTTP request headers.
		"""
		tmp = []
		exists = set(header.Header.all_lower())
		# --------------------------------
		# NOTE: Test-specific.
		for entry in headers:
			key, value = header.get_key_value(entry)
			if key:
				exists.add(key.lower())
				tmp.append(header.format_key_value(key, value))
		# --------------------------------
		# NOTE: User-supplied.
		for entry in self.__headers:
			key, value = header.get_key_value(entry)
			if key and key.lower() not in exists:
				tmp.append(header.format_key_value(key, value))
		# --------------------------------
		return tmp

	def __validate_cookies(self, cookies: list[str] = []) -> list[str]:
		"""
		Add user-supplied HTTP cookies to test-specific HTTP cookies.\n
		Important, user-supplied HTTP cookies cannot override test-specific HTTP cookies.
		"""
		tmp = []
		exists = set()
		# --------------------------------
		# NOTE: Test-specific.
		for entry in cookies:
			key, value = cookie.get_key_value(entry)
			if key:
				exists.add(key.lower())
				tmp.append(cookie.format_key_value(key, value))
		# --------------------------------
		# NOTE: User-supplied.
		for entry in self.__cookies:
			key, value = cookie.get_key_value(entry)
			if key and key.lower() not in exists:
				tmp.append(cookie.format_key_value(key, value))
		# --------------------------------
		return tmp

	def __get_user_agent(self):
		"""
		Get a [random] user agent.\n
		Returns an empty string if there are no user agents.
		"""
		user_agent = ""
		if self.__user_agents_len > 0:
			user_agent = self.__user_agents[random.randint(0, self.__user_agents_len - 1)]
		return user_agent

	# ------------------------------------

	def __send_pycurl(self, record: Records.Record, ignore = True, keep_response_headers = False, keep_response_body = False):
		"""
		Send an HTTP request using PycURL.
		"""
		curl    = None
		headers = None
		body    = None
		try:
			# ----------------------------
			self.__wait()
			# ----------------------------
			curl    = pycurl.Curl()
			headers = io.BytesIO()
			body    = io.BytesIO()
			# ----------------------------
			curl.setopt(pycurl.HEADERFUNCTION, headers.write            )
			curl.setopt(pycurl.WRITEFUNCTION , body.write               )
			curl.setopt(pycurl.FOLLOWLOCATION, self.__allow_redirects   )
			curl.setopt(pycurl.MAXREDIRS     , self.__max_redirects     )
			curl.setopt(pycurl.CONNECTTIMEOUT, self.__connect_timeout   )
			curl.setopt(pycurl.TIMEOUT       , self.__read_timeout      )
			curl.setopt(pycurl.PATH_AS_IS    , True                     ) # NOTE: Avoiding URL normalization.
			curl.setopt(pycurl.URL           , record.url               )
			curl.setopt(pycurl.CUSTOMREQUEST , record.method            )
			curl.setopt(pycurl.NOBODY        , record.method in ["HEAD"])
			curl.setopt(pycurl.COOKIESESSION , True                     )
			curl.setopt(pycurl.COOKIEJAR     , ""                       ) # NOTE: Setting an empty string to use in-memory storage.
			# ----------------------------
			if not self.__verify:
				curl.setopt(pycurl.SSL_VERIFYHOST      , False)
				curl.setopt(pycurl.SSL_VERIFYPEER      , False)
				curl.setopt(pycurl.PROXY_SSL_VERIFYHOST, False)
				curl.setopt(pycurl.PROXY_SSL_VERIFYPEER, False)
			# ----------------------------
			# NOTE: If 'User-Agent' HTTP request header is set in 'record.headers', it will override the one from 'record.user_agent'.
			# NOTE: If 'Cookie' HTTP request header is set in 'record.headers', it will override the one from 'record.cookie'.
			# NOTE: Where applicable, encode Unicode characters.
			curl.setopt(pycurl.PROXY     , record.proxy                           if record.proxy      else ""  )
			curl.setopt(pycurl.USERAGENT , record.user_agent                      if record.user_agent else ""  )
			curl.setopt(pycurl.COOKIE    , cookie.to_string(record.cookies)       if record.cookies    else None)
			curl.setopt(pycurl.HTTPHEADER, encode.encode_multiple(record.headers) if record.headers    else None)
			# ----------------------------
			# NOTE: If no 'Content-Type' HTTP request header is set, 'Content-Type: application/x-www-form-urlencoded' is set by default.
			if record.body:
				curl.setopt(pycurl.POST      , True       )
				curl.setopt(pycurl.POSTFIELDS, record.body)
			# ----------------------------
			curl.perform()
			# ----------------------------
			record.status = int(curl.getinfo(pycurl.RESPONSE_CODE))
			record.length = int(curl.getinfo(pycurl.SIZE_DOWNLOAD))
			# ----------------------------
			# NOTE: Does not automatically decode the response headers nor body.
			record.response_headers, ignored      = encode.decode(headers.getvalue())
			record.response        , record.error = encode.decode(body.getvalue())
			# ----------------------------
			self.__validate_response(record, ignore, keep_response_headers, keep_response_body)
			# ----------------------------
		except (pycurl.error, OSError) as ex:
			# ----------------------------
			record.error  = str(ex)
			record.status = general.ErrorCode.ERROR.value
			# ----------------------------
		finally:
			# ----------------------------
			if body:
				body.close()
			# ----------------------------
			if headers:
				headers.close()
			# ----------------------------
			if curl:
				curl.close()
			# ----------------------------
		return record

	def __send_python_requests(self, record: Records.Record, ignore = True, keep_response_headers = False, keep_response_body = False):
		"""
		Send an HTTP request using Python Requests.
		"""
		session  = None
		response = None
		try:
			# ----------------------------
			self.__wait()
			# ----------------------------
			session                 = requests.Session()
			session.verify          = self.__verify
			session.max_redirects   = self.__max_redirects
			session.proxies["http"] = session.proxies["https"] = record.proxy
			session.cookies.update(cookie.to_dict_duplicate(record.cookies))
			# ----------------------------
			# NOTE: If 'User-Agent' HTTP request header is set in 'record.headers', it will override the one from 'record.user_agent'.
			# NOTE: If 'Cookie' HTTP request header is set in 'record.headers', it will override the one from 'record.cookie'.
			# NOTE: Where applicable, encode Unicode characters.
			# NOTE: No 'Content-Type' HTTP request header is set by default.
			request = requests.Request(
				method = record.method,
				url    = record.url,
				data   = record.body
			)
			if record.user_agent:
				request.headers[header.Header.USER_AGENT.value] = record.user_agent
			for key, value in header.to_dict_duplicate(record.headers).items():
				request.headers[key] = encode.encode(value)
			# ----------------------------
			# NOTE: Avoiding URL normalization. Similar to '--path-as-is' in PycURL.
			prepared_request     = session.prepare_request(request)
			prepared_request.url = record.url
			# ----------------------------
			response = session.send(
				request         = prepared_request,
				allow_redirects = self.__allow_redirects,
				timeout         = (self.__connect_timeout, self.__read_timeout)
			)
			# ----------------------------
			record.status = response.status_code
			record.length = len(response.content)
			# ----------------------------
			# NOTE: Does automatically decode the response headers and body.
			record.response_headers = dict(response.headers)
			record.response         = response.text
			# ----------------------------
			self.__validate_response(record, ignore, keep_response_headers, keep_response_body)
			# ----------------------------
		except (requests.exceptions.RequestException, requests.packages.urllib3.exceptions.HTTPError) as ex:
			# ----------------------------
			record.error  = str(ex)
			record.status = general.ErrorCode.ERROR.value
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

	def __send_http_client(self, record: Records.Record, ignore = True, keep_response_headers = False, keep_response_body = False):
		"""
		Send an HTTP request using HTTP Client.\n
		Used to test HTTP/1.0 protocol downgrades.\n
		Does not support a web proxy.
		"""
		connection = None
		response   = None
		try:
			# ----------------------------
			self.__wait()
			# ----------------------------
			"""
			NOTE: For debugging.
			url        = u.URL(record.url)
			proxy      = u.URL(record.proxy)
			connection = connection = http.client.HTTPSConnection(proxy.domain.domain, proxy.port, timeout = self.__connect_timeout, context = None if self.__verify else ssl._create_unverified_context())
			connection.set_tunnel(url.domain.domain, url.port)
			"""
			url        = URL(record.url)
			connection = http.client.HTTPSConnection(url.domain.domain, url.port, timeout = self.__connect_timeout, context = None if self.__verify else ssl._create_unverified_context()) if url.is_https() else http.client.HTTPConnection(url.domain.domain, url.port, timeout = self.__connect_timeout)
			# ----------------------------
			connection._http_vsn     = 10
			connection._http_vsn_str = "HTTP/1.0"
			# ----------------------------
			# NOTE: If 'User-Agent' HTTP request header is set in 'record.headers', it will override the one from 'record.user_agent'.
			# NOTE: If 'Cookie' HTTP request header is set in 'record.headers', it will override the one from 'record.cookie'.
			# NOTE: Value encoding is not supported.
			headers = {}
			if record.user_agent:
				headers[header.Header.USER_AGENT.value] = record.user_agent
			if record.cookies:
				headers[header.Header.COOKIE.value] = cookie.to_string(record.cookies)
			for key, value in header.to_dict_duplicate(record.headers).items():
				headers[key] = value
			# ----------------------------
			# NOTE: Does not normalize URLs.
			# NOTE: No 'Content-Type' HTTP request header is set by default.
			connection.request(
				method  = record.method,
				url     = url.path.path,
				headers = headers,
				body    = record.body or None
			)
			# ----------------------------
			# NOTE: Does not automatically decode the response body.
			response                      = connection.getresponse()
			record.status                 = response.status
			record.response_headers       = dict(response.getheaders())
			record.response               = response.read()
			record.length                 = len(record.response)
			record.response, record.error = encode.decode(record.response)
			# ----------------------------
			self.__validate_response(record, ignore, keep_response_headers, keep_response_body)
			# ----------------------------
		except (http.client.HTTPException, OSError) as ex:
			# ----------------------------
			record.error  = str(ex)
			record.status = general.ErrorCode.ERROR.value
			# ----------------------------
		finally:
			# ----------------------------
			if response:
				response.close()
			# ----------------------------
			if connection:
				connection.close()
			# ----------------------------
		return record

	def __validate_response(self, record: Records.Record, ignore = True, keep_response_headers = False, keep_response_body = False):
		"""
		Validate an HTTP response.
		"""
		# --------------------------------
		if record.error:
			record.status = general.ErrorCode.ERROR.value
		elif ignore and (record.length in self.__content_lengths or self.__ignore and grep.search(record.response, self.__ignore)):
			record.status = general.ErrorCode.IGNORED.value
		# --------------------------------
		if not keep_response_headers:
			record.response_headers = ""
		if not keep_response_body:
			record.response = ""
		# --------------------------------

	# ------------------------------------

	def __prepare_test_records(self):
		"""
		Prepare test records.
		"""
		print(general.get_timestamp("Preparing test records..."))
		# --------------------------------
		if self.__check_scope([general.Test.PROTOCOLS]):
			# NOTE: Test HTTP and HTTPS protocols using an IP address and domain name.
			self.__records(
				id  = "PROTOCOLS-1",
				url = array.unique(self.__url.full.domain.all + self.__url.full.ip.all)
			)
			# NOTE: Test an HTTP/1.0 protocol downgrade without the 'Host' HTTP request header, using an IP address and domain name.
			self.__records(
				id     = "PROTOCOLS-2",
				url    = self.__url.full.initial.all,
				engine = general.Engine.HTTP_CLIENT
			)
		# --------------------------------
		if self.__check_scope([general.Test.METHODS]):
			# NOTE: Test the allowed HTTP methods.
			self.__records(
				id     = "METHODS-1",
				url    = self.__url.full.initial.domain,
				method = self.__allowed_methods
			)
			# NOTE: Test the allowed HTTP methods using the 'Content-Length: 0' HTTP request header.
			self.__records(
				id      = "METHODS-2",
				url     = self.__url.full.initial.domain,
				method  = self.__allowed_methods,
				headers = ["Content-Length: 0"]
			)
			# NOTE: Test Cross-Site Tracing (XST) using the HTTP TRACE and TRACK methods.
			# NOTE: To confirm the vulnerability, check if the 'XST: XST' HTTP response header is sent back.
			self.__records(
				id      = "METHODS-3",
				url     = self.__url.full.initial.domain,
				method  = ["TRACE", "TRACK"],
				headers = ["XST: XST"]
			)
		# --------------------------------
		if self.__check_scope([general.Test.UPLOADS]):
			# NOTE: Test a text file upload recursively for each directory in the URL path using the HTTP PUT method.
			# NOTE: Semi-colon in 'Content-Type;' will expand to an empty HTTP request header.
			self.__records(
				id      = "UPLOADS-1",
				url     = test.get_file_upload_urls(self.__url, "/pentest.txt"),
				method  = "PUT",
				headers = ["Content-Type;", "Content-Type: text/plain"],
				body    = "pentest"
			)
		# --------------------------------
		if self.__check_scope([general.Test.METHOD_OVERRIDES]):
			# NOTE: Test HTTP method overrides using URL query string parameters.
			self.__records(
				id     = "METHOD-OVERRIDES-1",
				url    = test.get_method_override_urls(self.__url, self.__allowed_methods + value.values.methods),
				method = self.__allowed_methods
			)
			# NOTE: Test HTTP method overrides using HTTP request headers.
			self.__records(
				id      = "METHOD-OVERRIDES-2",
				url     = self.__url.full.initial.domain,
				method  = self.__allowed_methods,
				headers = test.get_method_override_headers(self.__allowed_methods + value.values.methods)
			)
			# NOTE: Test HTTP method overrides using HTTP request bodies.
			self.__records(
				id      = "METHOD-OVERRIDES-3",
				url     = self.__url.full.initial.domain,
				method  = "POST",
				headers = ["Content-Type: application/x-www-form-urlencoded"],
				body    = test.get_method_override_bodies(self.__allowed_methods + value.values.methods)
			)
		# --------------------------------
		if self.__check_scope([general.Test.SCHEME_OVERRIDES]):
			# NOTE: Test URL scheme overrides using HTTP request headers, from HTTPS to HTTP.
			self.__records(
				id      = "SCHEME-OVERRIDES-1",
				url     = self.__url.full.domain.https,
				headers = test.get_scheme_override_headers(Scheme.HTTP)
			)
			# NOTE: Test URL scheme overrides using HTTP request headers, from HTTP to HTTPS.
			self.__records(
				id      = "SCHEME-OVERRIDES-2",
				url     = self.__url.full.domain.http,
				headers = test.get_scheme_override_headers(Scheme.HTTPS)
			)
		# --------------------------------
		if self.__check_scope([general.Test.PORT_OVERRIDES]):
			# NOTE: Test port overrides using HTTP request headers.
			self.__records(
				id      = "PORT-OVERRIDES-1",
				url     = self.__url.full.initial.domain,
				headers = test.get_port_override_headers([self.__url.port] + value.values.ports)
			)
		# --------------------------------
		if self.__check_scope([general.Test.HOST_OVERRIDES]):
			# NOTE: Test HTTP host overrides using HTTP request headers.
			self.__records(
				id      = "HOST-OVERRIDES-1",
				url     = self.__url.full.initial.domain,
				headers = test.get_host_override_headers(value.get_hosts(self.__url, self.__evil))
			)
			# NOTE: Test HTTP host overrides using two 'Host' HTTP request headers.
			self.__records(
				id      = "HOST-OVERRIDES-2",
				url     = self.__url.full.initial.domain,
				headers = test.get_two_host_headers(self.__url, self.__evil),
				engine  = general.Engine.PYTHON_REQUESTS
			)
		# --------------------------------
		if self.__check_scope([general.Test.PATH_OVERRIDES]):
			# NOTE: Test URL path overrides using HTTP request headers with relative URL paths, using an accessible URL.
			if self.__accessible:
				self.__records(
					id      = "PATH-OVERRIDES-1",
					url     = self.__accessible,
					headers = test.get_path_override_headers(value.get_relative_paths(self.__url))
				)
			# NOTE: Test URL path overrides using HTTP request headers with relative URL paths, using a root URL.
			self.__records(
				id      = "PATH-OVERRIDES-2",
				url     = self.__url.domain.scheme_domain_port,
				headers = test.get_path_override_headers(value.get_relative_paths(self.__url))
			)
			# NOTE: Test URL path overrides using HTTP request headers with relative URL paths, using a full URL.
			self.__records(
				id      = "PATH-OVERRIDES-3",
				url     = self.__url.full.initial.domain,
				headers = test.get_path_override_headers(value.get_relative_paths(self.__url))
			)
		# --------------------------------
		if self.__check_scope([general.Test.HEADERS]):
			# NOTE: Test HTTP request headers with IP addresses.
			self.__records(
				id      = "HEADERS-1",
				url     = self.__url.full.initial.domain,
				headers = test.get_ip_headers(value.get_ips(self.__url, self.__evil))
			)
			# NOTE: Test HTTP request headers with comma-separated IP addresses.
			self.__records(
				id      = "HEADERS-2",
				url     = self.__url.full.initial.domain,
				headers = test.get_multi_ip_headers(value.get_multi_ips(self.__url))
			)
			# NOTE: Test HTTP request headers with IP addresses and domain names.
			self.__records(
				id      = "HEADERS-3",
				url     = self.__url.full.initial.domain,
				headers = test.get_host_override_headers(value.get_hosts(self.__url, self.__evil))
			)
			# NOTE: Test HTTP request headers with IP addresses and domain names.
			self.__records(
				id      = "HEADERS-4",
				url     = self.__url.full.initial.domain,
				headers = test.get_host_headers(value.get_hosts(self.__url, self.__evil))
			)
			# NOTE: Test HTTP request headers with root URLs.
			self.__records(
				id      = "HEADERS-5",
				url     = self.__url.full.initial.domain,
				headers = test.get_root_url_headers(value.get_root_urls(self.__url, self.__evil))
			)
			# NOTE: Test HTTP request headers with full URLs.
			self.__records(
				id      = "HEADERS-6",
				url     = self.__url.full.initial.domain,
				headers = test.get_path_override_headers(value.get_full_urls(self.__url, self.__evil))
			)
			# NOTE: Test HTTP request headers with full URLs.
			self.__records(
				id      = "HEADERS-7",
				url     = self.__url.full.initial.domain,
				headers = test.get_full_url_headers(value.get_full_urls(self.__url, self.__evil))
			)
			# NOTE: Test HTTP request headers with special values.
			self.__records(
				id      = "HEADERS-8",
				url     = self.__url.full.initial.domain,
				headers = test.get_special_headers(self.__url, self.__evil)
			)
		# --------------------------------
		if self.__check_scope([general.Test.IP_VALUES]):
			if self.__values:
				# NOTE: Test HTTP request headers with user-supplied IP addresses.
				self.__records(
					id      = "IP-VALUES-1",
					url     = self.__url.full.initial.domain,
					headers = test.get_ip_headers(self.__values)
				)
		if self.__check_scope([general.Test.HOST_VALUES]):
			if self.__values:
				# NOTE: Test HTTP request headers with user-supplied IP addresses and domain names.
				self.__records(
					id      = "HOST-VALUES-1",
					url     = self.__url.full.initial.domain,
					headers = test.get_host_override_headers(self.__values)
				)
				# NOTE: Test HTTP request headers with user-supplied IP addresses and domain names.
				self.__records(
					id      = "HOST-VALUES-2",
					url     = self.__url.full.initial.domain,
					headers = test.get_host_headers(self.__values)
				)
		# --------------------------------
		if self.__check_scope([general.Test.URL_VALUES]):
			if self.__values:
				# NOTE: Test HTTP request headers with user-supplied root URLs.
				self.__records(
					id      = "URL-VALUES-1",
					url     = self.__url.full.initial.domain,
					headers = test.get_root_url_headers(self.__values)
				)
				# NOTE: Test HTTP request headers with user-supplied full URLs.
				self.__records(
					id      = "URL-VALUES-2",
					url     = self.__url.full.initial.domain,
					headers = test.get_path_override_headers(self.__values)
				)
				# NOTE: Test HTTP request headers with user-supplied full URLs.
				self.__records(
					id      = "URL-VALUES-3",
					url     = self.__url.full.initial.domain,
					headers = test.get_full_url_headers(self.__values)
				)
		# --------------------------------
		if self.__check_scope([general.Test.PATHS, general.Test.PATHS_RAM]):
			# NOTE: Test URL path bypasses.
			self.__records(
				id  = "PATHS-1",
				url = test.get_path_bypass_urls(self.__url, general.Test.PATHS not in self.__tests)
			)
		# --------------------------------
		if self.__check_scope([general.Test.ENCODINGS]):
			# NOTE: Test URL host and path transformations and encodings.
			self.__records(
				id     = "ENCODINGS-1",
				url    = test.get_encoded_urls(self.__url),
				engine = general.Engine.PYCURL
			)
		# --------------------------------
		if self.__check_scope([general.Test.BASIC_AUTHS]):
			# NOTE: Test basic authentication/authorization using HTTP request headers with null values and predefined Base64 encoded credentials.
			self.__records(
				id      = "BASIC-AUTHS-1",
				url     = self.__url.full.initial.domain,
				headers = test.get_basic_auth_headers(value.get_basic_credentials())
			)
		# --------------------------------
		if self.__check_scope([general.Test.BEARER_AUTHS]):
			# NOTE: Test bearer authentication/authorization using HTTP request headers with null values, malformed JWTs, and predefined JWTs.
			self.__records(
				id      = "BEARER-AUTHS-1",
				url     = self.__url.full.initial.domain,
				headers = test.get_bearer_auth_headers(value.get_bearer_credentials(self.__url, self.__evil))
			)
		# --------------------------------
		if self.__check_scope([general.Test.REDIRECTS]):
			# NOTE: Test open redirects using HTTP request headers with redirect IP addresses.
			self.__records(
				id      = "REDIRECTS-1",
				url     = self.__url.full.initial.domain,
				headers = test.get_ip_headers(value.get_redirect_ips(self.__url, self.__evil))
			)
			# NOTE: Test open redirects using HTTP request headers with redirect IP addresses and domain names.
			self.__records(
				id      = "REDIRECTS-2",
				url     = self.__url.full.initial.domain,
				headers = test.get_host_override_headers(value.get_redirect_hosts(self.__url, self.__evil))
			)
			# NOTE: Test open redirects using HTTP request headers with redirect IP addresses and domain names.
			self.__records(
				id      = "REDIRECTS-3",
				url     = self.__url.full.initial.domain,
				headers = test.get_host_headers(value.get_redirect_hosts(self.__url, self.__evil))
			)
			# NOTE: Test open redirects using HTTP request headers with redirect root URLs.
			self.__records(
				id      = "REDIRECTS-4",
				url     = self.__url.full.initial.domain,
				headers = test.get_root_url_headers(value.get_redirect_root_urls(self.__url, self.__evil))
			)
			# NOTE: Test open redirects using HTTP request headers with redirect full URLs.
			self.__records(
				id      = "REDIRECTS-5",
				url     = self.__url.full.initial.domain,
				headers = test.get_path_override_headers(value.get_redirect_full_urls(self.__url, self.__evil))
			)
			# NOTE: Test open redirects using HTTP request headers with redirect full URLs.
			self.__records(
				id      = "REDIRECTS-6",
				url     = self.__url.full.initial.domain,
				headers = test.get_full_url_headers(value.get_redirect_full_urls(self.__url, self.__evil))
			)
		# --------------------------------
		if self.__check_scope([general.Test.PARSERS]):
			# NOTE: Test broken URL parsers using HTTP request headers with broken IP addresses.
			self.__records(
				id      = "PARSERS-1",
				url     = self.__url.full.initial.domain,
				headers = test.get_ip_headers(value.get_broken_ips(self.__url, self.__evil))
			)
			# NOTE: Test broken URL parsers using HTTP request headers with broken IP addresses and domain names.
			self.__records(
				id      = "PARSERS-2",
				url     = self.__url.full.initial.domain,
				headers = test.get_host_override_headers(value.get_broken_hosts(self.__url, self.__evil))
			)
			# NOTE: Test broken URL parsers using HTTP request headers with broken IP addresses and domain names.
			self.__records(
				id      = "PARSERS-3",
				url     = self.__url.full.initial.domain,
				headers = test.get_host_headers(value.get_broken_hosts(self.__url, self.__evil))
			)
			# NOTE: Test broken URL parsers using HTTP request headers with broken root URLs.
			self.__records(
				id      = "PARSERS-4",
				url     = self.__url.full.initial.domain,
				headers = test.get_root_url_headers(value.get_broken_root_urls(self.__url, self.__evil))
			)
			# NOTE: Test broken URL parsers using HTTP request headers with broken full URLs.
			self.__records(
				id      = "PARSERS-5",
				url     = self.__url.full.initial.domain,
				headers = test.get_path_override_headers(value.get_broken_full_urls(self.__url, self.__evil))
			)
			# NOTE: Test broken URL parsers using HTTP request headers with broken full URLs.
			self.__records(
				id      = "PARSERS-6",
				url     = self.__url.full.initial.domain,
				headers = test.get_full_url_headers(value.get_broken_full_urls(self.__url, self.__evil))
			)
