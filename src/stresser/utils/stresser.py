#!/usr/bin/env python3

from .       import array, cookie, encode, file, general, grep, header, report
from .record import Records
from .url    import URL

import alive_progress, concurrent.futures, http.client, io, pycurl, random, requests, ssl

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# ----------------------------------------

class Stresser:

	def __init__(
		self,
		url              : str,
		ignore_parameters: bool,
		ignore_requests  : bool,
		force            : str,
		headers          : list[str],
		cookies          : list[str],
		ignore_regex     : str,
		content_lengths  : list[int | general.ContentLength],
		request_timeout  : int,
		repeat           : int,
		user_agents      : list[str],
		proxy            : str,
		status_codes     : list[general.StatusCode],
		directory        : str,
		debug            : bool
	):
		"""
		Class for managing the tool.
		"""
		self.__url             = URL(url, ignore_parameters)
		self.__force           = force
		self.__headers         = headers
		self.__cookies         = cookies
		self.__ignore          = ignore_regex
		self.__content_lengths = content_lengths
		self.__repeat          = repeat
		self.__user_agents     = user_agents
		self.__user_agents_len = len(self.__user_agents)
		self.__proxy           = proxy
		self.__status_codes    = status_codes
		self.__directory       = directory
		self.__debug           = debug
		# --------------------------------
		self.__engine          = general.Engine.PYCURL if ignore_requests else general.Engine.PYTHON_REQUESTS
		self.__verify          = False
		self.__allow_redirects = True
		self.__max_redirects   = 10
		self.__connect_timeout = request_timeout
		self.__read_timeout    = request_timeout
		# --------------------------------
		self.__default_method  = "GET"
		self.__main_method     = self.__force or self.__default_method
		# --------------------------------
		self.__collection      = Records()

	# ------------------------------------

	def __replace_content_length(self, content_length_enum: general.ContentLength, content_length_value: int):
		"""
		Replace a content length enum with a content length value in the content lengths list.
		"""
		self.__content_lengths[self.__content_lengths.index(content_length_enum)] = content_length_value
		self.__content_lengths = list(set(self.__content_lengths))

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
		if self.__validate_inaccessible_url():
			self.__prepare_test_records()
			if not self.__collection.len() > 0:
				print("No test records were created")
			else:
				self.__collection.unique()
				general.print_cyan(f"Number of created test records: {self.__collection.sum()}")
				if dump:
					print(general.get_timestamp("Dumping the test records in the output file..."))
					results = self.__collection.get_tests()
				else:
					self.__collection.duplicate()
					self.__run_tests(threads)
					self.__collection.flag_duplicates()
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

	# ------------------------------------

	def __send(self, url: str, method = "", headers: list[str] = [], cookies: list[str] = [], body = "", ignore = True, keep_response_headers = False, keep_response_body = False) -> Records.Record:
		"""
		Send an HTTP request using the default HTTP request engine.\n
		Used for initial validation.
		"""
		record = self.__record("SYSTEM-0", url, method, headers, cookies, body, repeat = 1)
		method = getattr(self, record.engine.get_method())
		record = method(record, ignore, keep_response_headers, keep_response_body, False)
		self.__print_debug(record)
		return record

	# ------------------------------------

	def __records(self, id: str, url: str | list[str], method: str | list[str] = [""], headers: list[str] | list[list[str]] = [[]], cookies: list[str] | list[list[str]] = [[]], body: str | list[str] = [""], engine: general.Engine = None, repeat = 0):
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
							self.__collection.append(self.__record(id, __url, __method, __headers, __cookies, __body, engine, repeat))

	def __record(self, id: str, url: str, method = "", headers: list[str] = [], cookies: list[str] = [], body = "", engine: general.Engine = None, repeat = 0):
		"""
		Get a test record.
		"""
		return Records.Record(id, url, method or self.__main_method, self.__validate_headers(headers), self.__validate_cookies(cookies), body, self.__get_user_agent(), self.__proxy, engine or self.__engine, repeat or self.__repeat)

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

	def __send_pycurl(self, record: Records.Record, ignore = True, keep_response_headers = False, keep_response_body = False, save_to_file = True):
		"""
		Send an HTTP request using PycURL.
		"""
		curl    = None
		headers = None
		body    = None
		try:
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
			self.__validate_response(record, ignore, keep_response_headers, keep_response_body, save_to_file)
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

	def __send_python_requests(self, record: Records.Record, ignore = True, keep_response_headers = False, keep_response_body = False, save_to_file = True):
		"""
		Send an HTTP request using Python Requests.
		"""
		session  = None
		response = None
		try:
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
			self.__validate_response(record, ignore, keep_response_headers, keep_response_body, save_to_file)
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

	def __send_http_client(self, record: Records.Record, ignore = True, keep_response_headers = False, keep_response_body = False, save_to_file = True):
		"""
		Send an HTTP request using HTTP Client.\n
		Used to test HTTP/1.0 protocol downgrades.\n
		Does not support a web proxy.
		"""
		connection = None
		response   = None
		try:
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
			self.__validate_response(record, ignore, keep_response_headers, keep_response_body, save_to_file)
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

	def __validate_response(self, record: Records.Record, ignore = True, keep_response_headers = False, keep_response_body = False, save_to_file = True):
		"""
		Validate an HTTP response.
		"""
		# --------------------------------
		if record.error:
			record.status = general.ErrorCode.ERROR.value
		elif ignore and (record.length in self.__content_lengths or self.__ignore and grep.search(record.response, self.__ignore)):
			record.status = general.ErrorCode.IGNORED.value
		elif save_to_file:
			record.update_id()
			if general.StatusCode.from_status_code(record.status) in self.__status_codes:
				file.write_result_silent(record, self.__directory)
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
		self.__records(
			id  = "STRESSING-1",
			url = self.__url.full.initial.domain,
		)
