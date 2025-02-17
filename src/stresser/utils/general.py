#!/usr/bin/env python3

import colorama, datetime, enum, json, termcolor, typing

colorama.init(autoreset = True)

class ContentLength(enum.Enum):
	"""
	Enum containing supported content lengths.
	"""
	INITIAL = "initial"

	@classmethod
	def all(cls):
		"""
		Get all supported content lengths.
		"""
		return [
			cls.INITIAL
		]

	@classmethod
	def all_lower(cls):
		"""
		Get all supported content lengths in lowercase.
		"""
		return [entry.value.lower() for entry in cls.all()]

# ----------------------------------------

class UserAgent(enum.Enum):
	"""
	Enum containing supported user agents.
	"""
	RANDOM     = "random"
	RANDOM_ALL = "random-all"

# ----------------------------------------

class StatusCode(enum.Enum):
	"""
	Enum containing supported HTTP response status codes.
	"""
	STATUS_1XX = "1xx"
	STATUS_2XX = "2xx"
	STATUS_3XX = "3xx"
	STATUS_4XX = "4xx"
	STATUS_5XX = "5xx"
	ALL        = "all"

	@classmethod
	def all(cls):
		"""
		Get all supported HTTP response status codes.
		"""
		return [
			cls.STATUS_1XX,
			cls.STATUS_2XX,
			cls.STATUS_3XX,
			cls.STATUS_4XX,
			cls.STATUS_5XX
		]

	@classmethod
	def all_lower(cls):
		"""
		Get all supported HTTP response status codes in lowercase.
		"""
		return [entry.value.lower() for entry in cls.all()]

	@classmethod
	def get_color_name(cls, status_code: int) -> str:
		"""
		Get the color based on the specified HTTP response status code.
		"""
		if status_code < 100 or status_code >= 600:
			return colorama.Fore.WHITE
		elif status_code >= 500:
			return colorama.Fore.BLUE
		elif status_code >= 400:
			return colorama.Fore.RED
		elif status_code >= 300:
			return colorama.Fore.YELLOW
		elif status_code >= 200:
			return colorama.Fore.GREEN
		elif status_code >= 100:
			return colorama.Fore.WHITE

	@classmethod
	def from_status_code(cls, status_code: int) -> "StatusCode":
		"""
		Get the enum based on the specified HTTP response status code.
		"""
		if status_code < 100 or status_code >= 600:
			return None
		elif status_code >= 500:
			return cls.STATUS_5XX
		elif status_code >= 400:
			return cls.STATUS_4XX
		elif status_code >= 300:
			return cls.STATUS_3XX
		elif status_code >= 200:
			return cls.STATUS_2XX
		elif status_code >= 100:
			return cls.STATUS_1XX

# ----------------------------------------

class ErrorCode(enum.Enum):
	"""
	Enum containing custom error HTTP response status codes.
	"""
	DUPLICATE = -3
	IGNORED   = -2
	ERROR     = -1
	UNTESTED  =  0

	@classmethod
	def all(cls):
		"""
		Get all custom error HTTP response status code values.
		"""
		return [
			cls.DUPLICATE.value,
			cls.IGNORED.value,
			cls.ERROR.value,
			cls.UNTESTED.value
		]

	@classmethod
	def get_error_name(cls, status_code: int):
		"""
		Get the error name based on the specified HTTP response status code.
		"""
		if status_code in cls.all():
			return ErrorCode(status_code).name
		else:
			return str(status_code)

# ----------------------------------------

class Engine(str, enum.Enum):
	"""
	Enum containing HTTP request engines.
	"""
	PYTHON_REQUESTS = "python_requests"
	PYCURL          = "pycurl"
	HTTP_CLIENT     = "http_client"

	def get_title(self):
		"""
		Get the title to show.
		"""
		mapping = {
			Engine.PYTHON_REQUESTS: "Python Requests",
			Engine.PYCURL         : "PycURL",
			Engine.HTTP_CLIENT    : "HTTP Client"
		}
		return mapping[self]

	def get_method(self):
		"""
		Get the method name to call.
		"""
		mapping = {
			Engine.PYTHON_REQUESTS: "_Stresser__send_python_requests",
			Engine.PYCURL         : "_Stresser__send_pycurl",
			Engine.HTTP_CLIENT    : "_Stresser__send_http_client"
		}
		return mapping[self]

# ----------------------------------------

class UniqueString(str):
	"""
	Class that allows us to use duplicate keys in a dictionary.
	"""

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
				self.__lower = UniqueString(lower)
		return self.__lower

# ----------------------------------------

def get_timestamp(message: str):
	"""
	Get the current timestamp.
	"""
	return f"{datetime.datetime.now().strftime('%H:%M:%S')} - {message}"

def color(value: typing.Any, color_name: str):
	"""
	Color a value.
	"""
	return f"{color_name}{value}{colorama.Style.RESET_ALL}"

def color_multiple(values: list[typing.Any], color_name: str):
	"""
	Color multiple values.
	"""
	tmp = []
	for value in values:
		tmp.append(color(value, color_name))
	return tuple(tmp)

def print_error(message: str):
	"""
	Print an error message.
	"""
	print(f"ERROR: {message}")

def print_green(message: str):
	"""
	Print a message in green color.
	"""
	termcolor.cprint(message, "green")

def print_yellow(message: str):
	"""
	Print a message in yellow color.
	"""
	termcolor.cprint(message, "yellow")

def print_red(message: str):
	"""
	Print a message in red color.
	"""
	termcolor.cprint(message, "red")

def print_cyan(message: str):
	"""
	Print a message in cyan color.
	"""
	termcolor.cprint(message, "cyan")

def jdump(data: typing.Any):
	"""
	Serialize a data to a JSON string.
	"""
	return json.dumps(data, indent = 4, ensure_ascii = False)
