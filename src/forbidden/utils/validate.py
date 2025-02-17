#!/usr/bin/env python3

from . import array, config, cookie, file, general, grep, header, path, url

import argparse, bot_safe_agents, sys

class MyArgParser(argparse.ArgumentParser):

	def print_help(self):
		print(f"Forbidden {config.APP_VERSION} ( github.com/ivan-sincek/forbidden )")
		print("")
		print("Usage:   forbidden -u url                       -t tests [-f force] [-o out         ]")
		print("Example: forbidden -u https://example.com/admin -t all   [-f GET  ] [-o results.json]")
		print("")
		print("DESCRIPTION")
		print("    Bypass 4xx HTTP response status codes and more")
		print("URL")
		print("    Inaccessible URL")
		print("    -u, --url = https://example.com/admin | etc.")
		print("IGNORE PARAMETERS")
		print("    Ignore URL query string and fragment")
		print("    -ip, --ignore-parameters")
		print("IGNORE REQUESTS")
		print("    Where applicable, use PycURL instead of the default Python Requests engine")
		print("    -ir, --ignore-requests")
		print("TESTS")
		print("    Tests to run")
		print("    Specify '[ip-|host-|url-]values' to test HTTP request headers using only user-supplied values passed with the '-v' option")
		print("    Specify 'paths-ram' to use the battering ram attack or 'paths' to use the default cluster bomb attack")
		print("    Use comma-separated values")
		print("    -t, --tests = protocols | methods | uploads | [method-|scheme-|port-|host-|path-]overrides | headers | [ip-|host-|url-]values | paths[-ram] | encodings | [basic-|bearer-]auths | redirects | parsers | all")
		print("VALUES")
		print("    File containing HTTP request header values or a single value, e.g., internal IP, etc.")
		print("    Tests: all-values")
		print("    -v, --values = values.txt | 10.10.15.20 | example.local | https://example.local | etc.")
		print("FORCE")
		print("    Force an HTTP method for all non-specific tests")
		print("    -f, --force = GET | POST | CUSTOM | etc.")
		print("PATH")
		print("    Accessible URL path to test URL path overrides")
		print("    Tests: path-overrides")
		print(f"    Default: {(', ').join(config.ACCESSIBLE_PATHS)}")
		print("    -p, --path = /home | etc.")
		print("EVIL")
		print("    Evil URL or collaborator service")
		print("    Tests: host-overrides, headers, bearer-auths, redirects, parsers")
		print(f"    Default: {config.EVIL_URL}")
		print("    -e, --evil = https://xyz.interact.sh | https://xyz.burpcollaborator.net | etc.")
		print("HEADER")
		print("    Any number of extra HTTP request headers")
		print("    Extra HTTP request headers will not override test-specific HTTP request headers")
		print("    Semi-colon in, e.g., 'Content-Type;' will expand to an empty HTTP request header")
		print("    -H, --header = \"Authorization: Bearer ey...\" | Content-Type; | etc.")
		print("COOKIE")
		print("    Any number of extra HTTP cookies")
		print("    Extra HTTP cookies will not override test-specific HTTP cookies")
		print("    -b, --cookie = PHPSESSIONID=3301 | etc.")
		print("IGNORE")
		print("    RegEx to filter out false positive 200 OK results")
		print("    -i, --ignore = Inaccessible | \"Access Denied\" | \"Error: .+\" | etc.")
		print("CONTENT LENGTHS")
		print("    HTTP response content lengths to filter out false positive 200 OK results")
		print("    Specify 'initial' to ignore the content length of the initial HTTP response")
		print("    Specify 'path' to ignore the content length of the accessible URL's response")
		print("    Use comma-separated values")
		print("    -l, --content-lengths = 12 | initial | path | etc.")
		print("REQUEST TIMEOUT")
		print("    Request timeout in seconds")
		print("    Default: 60")
		print("    -rt, --request-timeout = 30 | 90 | etc.")
		print("THREADS")
		print("    Number of parallel threads to run")
		print("    Default: 5")
		print("    -th, --threads = 20 | etc.")
		print("SLEEP")
		print("    Sleep time in milliseconds before sending an HTTP request")
		print("    Intended for a single-thread use")
		print("    -s, --sleep = 500 | etc.")
		print("USER AGENT")
		print("    User agent to use")
		print(f"    Default: {config.USER_AGENT}")
		print("    -a, --user-agent = random[-all] | curl/3.30.1 | etc.")
		print("PROXY")
		print("    Web proxy to use")
		print("    -x, --proxy = http://127.0.0.1:8080 | etc.")
		print("HTTP RESPONSE STATUS CODES")
		print("    Include only specific HTTP response status codes in the results")
		print("    Default: 2xx, 3xx")
		print("    Use comma-separated values")
		print("    -sc, --status-codes = 1xx | 2xx | 3xx | 4xx | 5xx | all")
		print("SHOW TABLE")
		print("    Display the results in a table format instead of JSON format")
		print("    Intended for use on a wide screen")
		print("    -st, --show-table")
		print("OUT")
		print("    Output file")
		print("    -o, --out = results.json | etc.")
		print("DUMP")
		print("    Dump all the test records into the output file without running any")
		print("    -dmp, --dump")
		print("DEBUG")
		print("    Enable debug output")
		print("    -dbg, --debug")

	def error(self, message):
		if len(sys.argv) > 1:
			print("Missing a mandatory option (-u, -t) and/or optional (-ip, -ir, -v, -f, -p, -e, -H, -b, -i, -l, -rt, -th, -s, -a, -x, -sc, -st, -o, -dmp, -dbg)")
			print("Use -h or --help for more info")
		else:
			self.print_help()
		exit()

class Validate:

	def __init__(self):
		"""
		Class for validating and managing CLI arguments.
		"""
		self.__parser = MyArgParser()
		self.__parser.add_argument("-u"  , "--url"              , required = True , type   = str         , default = ""   )
		self.__parser.add_argument("-ip" , "--ignore-parameters", required = False, action = "store_true", default = False)
		self.__parser.add_argument("-ir" , "--ignore-requests"  , required = False, action = "store_true", default = False)
		self.__parser.add_argument("-t"  , "--tests"            , required = True , type   = str.lower   , default = ""   )
		self.__parser.add_argument("-v"  , "--values"           , required = False, type   = str         , default = ""   )
		self.__parser.add_argument("-f"  , "--force"            , required = False, type   = str.upper   , default = ""   )
		self.__parser.add_argument("-p"  , "--path"             , required = False, type   = str         , default = ""   )
		self.__parser.add_argument("-e"  , "--evil"             , required = False, type   = str         , default = ""   )
		self.__parser.add_argument("-H"  , "--header"           , required = False, action = "append"    , nargs   = "+"  )
		self.__parser.add_argument("-b"  , "--cookie"           , required = False, action = "append"    , nargs   = "+"  )
		self.__parser.add_argument("-i"  , "--ignore"           , required = False, type   = str         , default = ""   )
		self.__parser.add_argument("-l"  , "--content-lengths"  , required = False, type   = str.lower   , default = ""   )
		self.__parser.add_argument("-rt" , "--request-timeout"  , required = False, type   = str         , default = ""   )
		self.__parser.add_argument("-th" , "--threads"          , required = False, type   = str         , default = ""   )
		self.__parser.add_argument("-s"  , "--sleep"            , required = False, type   = str         , default = ""   )
		self.__parser.add_argument("-a"  , "--user-agent"       , required = False, type   = str         , default = ""   )
		self.__parser.add_argument("-x"  , "--proxy"            , required = False, type   = str         , default = ""   )
		self.__parser.add_argument("-sc" , "--status-codes"     , required = False, type   = str.lower   , default = ""   )
		self.__parser.add_argument("-st" , "--show-table"       , required = False, action = "store_true", default = False)
		self.__parser.add_argument("-o"  , "--out"              , required = False, type   = str         , default = ""   )
		self.__parser.add_argument("-dmp", "--dump"             , required = False, action = "store_true", default = False)
		self.__parser.add_argument("-dbg", "--debug"            , required = False, action = "store_true", default = False)

	def validate_args(self):
		"""
		Validate and return the CLI arguments.
		"""
		self.__success = True
		self.__args = self.__parser.parse_args()
		self.__validate_url()
		self.__validate_tests()
		self.__validate_values()
		self.__validate_force()
		self.__validate_path()
		self.__validate_evil()
		self.__validate_header()
		self.__validate_cookie()
		self.__validate_ignore()
		self.__validate_content_lengths()
		self.__validate_request_timeout()
		self.__validate_threads()
		self.__validate_sleep()
		self.__validate_user_agent()
		self.__validate_proxy()
		self.__validate_status_codes()
		self.__validate_dump()
		return self.__success, self.__args

	def __error(self, message: str):
		"""
		Set the success flag to 'False' to prevent the main task from executing, and print an error message.
		"""
		self.__success = False
		general.print_error(message)

	# ------------------------------------

	def __validate_url(self):
		success, message = url.validate(self.__args.url)
		if not success:
			self.__error(f"Inaccessible URL: {message}")

	def __validate_tests(self):
		tmp = []
		tests = array.remove_empty_strings(self.__args.tests.split(","))
		if not tests:
			self.__error("No tests were specified")
		else:
			supported = general.Test.all_lower()
			for test in tests:
				if test == general.Test.ALL.value:
					tmp.extend(general.Test.all())
				elif test == general.Test.ALL_OVERRIDES.value:
					tmp.extend(general.Test.all_overrides())
				elif test == general.Test.ALL_VALUES.value:
					tmp.extend(general.Test.all_values())
				elif test == general.Test.ALL_AUTHS.value:
					tmp.extend(general.Test.all_auths())
				elif test not in supported:
					self.__error("Supported tests are 'protocols', 'methods', 'uploads', '[method-|scheme-|port-|host-|path-]overrides', 'headers', '[ip-|host-|url-]values', 'paths[-ram]', 'encodings', '[basic-|bearer-]auths', 'redirects', 'parsers', or 'all'")
					break
				else:
					tmp.append(general.Test(test))
			tmp = array.unique(tmp)
		self.__args.tests = tmp

	def __validate_values(self):
		tmp = []
		if self.__args.values:
			if file.is_file(self.__args.values):
				success, message = file.validate(self.__args.values)
				if not success:
					self.__error(message)
				else:
					tmp = file.read_array(self.__args.values)
					if not tmp:
						self.__error(f"No values were found in \"{self.__args.values}\"")
			else:
				tmp = [self.__args.values]
		self.__args.values = tmp

	def __validate_force(self):
		if self.__args.force:
			self.__args.force = self.__args.force.strip()
			if not self.__args.force:
				self.__error("Forced HTTP method is not valid")

	def __validate_path(self):
		tmp = config.ACCESSIBLE_PATHS
		if self.__args.path:
			self.__args.path = self.__args.path.strip()
			if not self.__args.path:
				self.__error("Accessible path is not valid")
			else:
				tmp = [path.prepend_slash(path.replace_multiple_slashes(self.__args.path))]
		self.__args.path = tmp

	def __validate_evil(self):
		if self.__args.evil:
			success, message = url.validate(self.__args.evil)
			if not success:
				self.__error(f"Evil URL: {message}")
		else:
			self.__args.evil = config.EVIL_URL

	def __validate_header(self):
		tmp = []
		if self.__args.header:
			for entry in self.__args.header:
				key, value = header.get_key_value(entry[0])
				if not key:
					self.__error(f"Invalid HTTP request header: {entry[0]}")
					continue
				tmp.append(header.format_key_value(key, value))
		self.__args.header = tmp

	def __validate_cookie(self):
		tmp = []
		if self.__args.cookie:
			for entry in self.__args.cookie:
				key, value = cookie.get_key_value(entry[0])
				if not key:
					self.__error(f"Invalid HTTP cookie: {entry[0]}")
					continue
				tmp.append(cookie.format_key_value(key, value))
		self.__args.cookie = tmp

	def __validate_ignore(self):
		if self.__args.ignore:
			success, message = grep.validate(self.__args.ignore)
			if not success:
				self.__error(message)

	def __validate_content_lengths(self):
		tmp = []
		if self.__args.content_lengths:
			content_lengths = array.remove_empty_strings(self.__args.content_lengths.split(","))
			if not content_lengths:
				self.__error("No content lengths were specified")
			else:
				supported = general.ContentLength.all_lower()
				for content_length in content_lengths:
					if content_length in supported:
						tmp.append(general.ContentLength(content_length))
					elif not content_length.isdigit() or int(content_length) < 0:
						self.__error("Content lengths must be either 'initial', 'path', or numeric greater than or equal to zero")
						break
					else:
						tmp.append(int(content_length))
				tmp = array.unique(tmp)
		self.__args.content_lengths = tmp

	def __validate_request_timeout(self):
		tmp = 60
		if self.__args.request_timeout:
			if not self.__args.request_timeout.isdigit():
				self.__error("Request timeout must be numeric")
			else:
				tmp = int(self.__args.request_timeout)
				if tmp <= 0:
					self.__error("Request timeout must be greater than zero")
		self.__args.request_timeout = tmp

	def __validate_threads(self):
		tmp = 5
		if self.__args.threads:
			if not self.__args.threads.isdigit():
				self.__error("Number of parallel threads must be numeric")
			else:
				tmp = int(self.__args.threads)
				if tmp <= 0:
					self.__error("Number of parallel threads must be greater than zero")
		self.__args.threads = tmp

	def __validate_sleep(self):
		tmp = 0
		if self.__args.sleep:
			if not self.__args.sleep.isdigit():
				self.__error("Sleep time must be numeric")
			else:
				tmp = int(self.__args.sleep) / 1000
				if tmp <= 0:
					self.__error("Sleep time must be greater than zero")
		self.__args.sleep = tmp

	def __validate_user_agent(self):
		tmp = [config.USER_AGENT]
		if self.__args.user_agent:
			lower = self.__args.user_agent.lower()
			if lower == general.UserAgent.RANDOM_ALL.value:
				tmp = bot_safe_agents.get_all()
			elif lower == general.UserAgent.RANDOM.value:
				tmp = [bot_safe_agents.get_random()]
			else:
				tmp = [self.__args.user_agent]
		self.__args.user_agent = tmp

	def __validate_proxy(self):
		if self.__args.proxy:
			success, message = url.validate(self.__args.proxy)
			if not success:
				self.__error(f"Proxy URL: {message}")

	def __validate_status_codes(self):
		if self.__args.status_codes:
			tmp = []
			status_codes = array.remove_empty_strings(self.__args.status_codes.split(","))
			if not status_codes:
				self.__error("No HTTP response status codes were specified")
			else:
				supported = general.StatusCode.all_lower()
				for status_code in status_codes:
					if status_code == general.StatusCode.ALL.value:
						tmp.extend(general.StatusCode.all())
					elif status_code not in supported:
						self.__error("Supported HTTP response status codes are '1xx', '2xx', '3xx', '4xx', '5xx', or 'all'")
						break
					else:
						tmp.append(general.StatusCode(status_code))
				tmp = array.unique(tmp)
			self.__args.status_codes = tmp
		else:
			self.__args.status_codes = [general.StatusCode.STATUS_2XX, general.StatusCode.STATUS_3XX]

	def __validate_dump(self):
		if self.__args.dump and not self.__args.out:
			self.__error("Cannot dump the test records because the output file is not specified")
