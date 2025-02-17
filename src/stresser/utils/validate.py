#!/usr/bin/env python3

from . import array, config, cookie, directory, general, grep, header, url

import argparse, bot_safe_agents, sys

class MyArgParser(argparse.ArgumentParser):

	def print_help(self):
		print(f"Stresser {config.APP_VERSION} ( github.com/ivan-sincek/forbidden )")
		print("")
		print("Usage:   stresser -u url                       -r repeat -th threads -dir directory [-f force] [-o out         ]")
		print("Example: stresser -u https://example.com/admin -r 1000   -th 200     -dir results   [-f GET  ] [-o results.json]")
		print("")
		print("DESCRIPTION")
		print("    Bypass 4xx HTTP response status codes with stress testing")
		print("URL")
		print("    Inaccessible URL")
		print("    -u, --url = https://example.com/admin | etc.")
		print("IGNORE PARAMETERS")
		print("    Ignore URL query string and fragment")
		print("    -ip, --ignore-parameters")
		print("IGNORE REQUESTS")
		print("    Where applicable, use PycURL instead of the default Python Requests engine")
		print("    -ir, --ignore-requests")
		print("FORCE")
		print("    Force an HTTP method for all non-specific tests")
		print("    -f, --force = GET | POST | CUSTOM | etc.")
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
		print("    Use comma-separated values")
		print("    -l, --content-lengths = 12 | initial | etc.")
		print("REQUEST TIMEOUT")
		print("    Request timeout in seconds")
		print("    Default: 60")
		print("    -rt, --request-timeout = 30 | 90 | etc.")
		print("REPEAT")
		print("    Number of HTTP requests per test")
		print("    -r, --repeat = 1000 | etc.")
		print("THREADS")
		print("    Number of parallel threads to run")
		print("    -th, --threads = 20 | etc.")
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
		print("DIRECTORY")
		print("    Output directory")
		print("    All valid and unique HTTP responses will be saved in this directory")
		print("    -dir, --directory = results | etc.")
		print("DUMP")
		print("    Dump all the test records into the output file without running any")
		print("    -dmp, --dump")
		print("DEBUG")
		print("    Enable debug output")
		print("    -dbg, --debug")

	def error(self, message):
		if len(sys.argv) > 1:
			print("Missing a mandatory option (-u, -r, -th, -dir) and/or optional (-ip, -ir, -f, -H, -b, -i, -l, -rt, -a, -x, -sc, -st, -o, -dmp, -dbg)")
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
		self.__parser.add_argument("-f"  , "--force"            , required = False, type   = str.upper   , default = ""   )
		self.__parser.add_argument("-H"  , "--header"           , required = False, action = "append"    , nargs   = "+"  )
		self.__parser.add_argument("-b"  , "--cookie"           , required = False, action = "append"    , nargs   = "+"  )
		self.__parser.add_argument("-i"  , "--ignore"           , required = False, type   = str         , default = ""   )
		self.__parser.add_argument("-l"  , "--content-lengths"  , required = False, type   = str.lower   , default = ""   )
		self.__parser.add_argument("-rt" , "--request-timeout"  , required = False, type   = str         , default = ""   )
		self.__parser.add_argument("-r"  , "--repeat"           , required = False, type   = str         , default = ""   )
		self.__parser.add_argument("-th" , "--threads"          , required = False, type   = str         , default = ""   )
		self.__parser.add_argument("-a"  , "--user-agent"       , required = False, type   = str         , default = ""   )
		self.__parser.add_argument("-x"  , "--proxy"            , required = False, type   = str         , default = ""   )
		self.__parser.add_argument("-sc" , "--status-codes"     , required = False, type   = str.lower   , default = ""   )
		self.__parser.add_argument("-st" , "--show-table"       , required = False, action = "store_true", default = False)
		self.__parser.add_argument("-o"  , "--out"              , required = False, type   = str         , default = ""   )
		self.__parser.add_argument("-dir", "--directory"        , required = False, type   = str         , default = ""   )
		self.__parser.add_argument("-dmp", "--dump"             , required = False, action = "store_true", default = False)
		self.__parser.add_argument("-dbg", "--debug"            , required = False, action = "store_true", default = False)

	def validate_args(self):
		"""
		Validate and return the CLI arguments.
		"""
		self.__success = True
		self.__args = self.__parser.parse_args()
		self.__validate_url()
		self.__validate_force()
		self.__validate_header()
		self.__validate_cookie()
		self.__validate_ignore()
		self.__validate_content_lengths()
		self.__validate_request_timeout()
		self.__validate_repeat()
		self.__validate_threads()
		self.__validate_user_agent()
		self.__validate_proxy()
		self.__validate_status_codes()
		self.__validate_directory()
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

	def __validate_force(self):
		if self.__args.force:
			self.__args.force = self.__args.force.strip()
			if not self.__args.force:
				self.__error("Forced HTTP method is not valid")

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
						self.__error("Content lengths must be either 'initial' or numeric greater than or equal to zero")
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

	def __validate_repeat(self):
		if not self.__args.repeat.isdigit():
			self.__error("Number of HTTP requests per test must be numeric")
		else:
			self.__args.repeat = int(self.__args.repeat)
			if self.__args.repeat <= 0:
				self.__error("Number of HTTP requests per test must be greater than zero")

	def __validate_threads(self):
		if not self.__args.threads.isdigit():
			self.__error("Number of parallel threads must be numeric")
		else:
			self.__args.threads = int(self.__args.threads)
			if self.__args.threads <= 0:
				self.__error("Number of parallel threads must be greater than zero")

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

	def __validate_directory(self):
		if self.__args.directory:
			if not directory.is_directory(self.__args.directory):
				self.__error(f"\"{self.__args.directory}\" does not exist or is not a directory")

	def __validate_dump(self):
		if self.__args.dump and not self.__args.out:
			self.__error("Cannot dump the test records because the output file is not specified")
