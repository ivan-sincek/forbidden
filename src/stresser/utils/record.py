#!/usr/bin/env python3

from . import general, grep

import copy, typing

__QUOTE = "'"
"""
Quotes used in 'record.command', i.e., in a cURL command.
"""

def set_opt(value: typing.Any, opt = ""):
	"""
	Enclose a value in quotes, escape the inner quotes, and append it to an option - if specified.
	"""
	tmp = __QUOTE + str(value).replace(__QUOTE, f"\\{__QUOTE}") + __QUOTE
	if opt:
		tmp = f"{opt} {tmp}"
	return tmp

# ----------------------------------------

class Records:

	def __init__(self):
		"""
		Class for storing test records.
		"""
		self.__records: list[Records.Record] = []

	def get(self):
		"""
		Get all test records.
		"""
		return self.__records

	def get_valid(self):
		"""
		Get only valid test records.
		"""
		return [record for record in self.__records if record.is_valid()]

	def get_tests(self):
		"""
		Get all test records as a JSON-compatible list.
		"""
		return [record.to_test() for record in self.__records]

	def append(self, record: "Records.Record"):
		"""
		Append a test record to the records.
		"""
		self.__records.append(record)

	def sum(self):
		"""
		Get the total number of test records.
		"""
		return sum([record.repeat for record in self.__records])

	def len(self):
		"""
		Get the total number of test records.
		"""
		return len(self.__records)

	def unique(self):
		"""
		Remove duplicate test records.\n
		Duplicates are filtered based on 'record.command'.
		"""
		tmp = []
		exists = set()
		for record in self.__records:
			command = grep.replace(record.command, set_opt(".+?", "-A")) # NOTE: Ignoring user agents as they could all be random / unique.
			if command not in exists and not exists.add(command):
				tmp.append(record)
		self.__records = tmp

	def duplicate(self):
		"""
		Create duplicates of each test record as specified in 'record.repeat'.
		"""
		tmp = []
		for record in self.__records:
			for _ in range(record.repeat):
				tmp.append(copy.deepcopy(record))
		self.__records = tmp

	def flag_duplicates(self):
		"""
		Flag duplicate test records.\n
		Duplicates are filtered based on 'record.status' and 'record.length'.
		"""
		exists = set()
		for record in self.__records:
			if not record.status > 0 or (record.id not in exists and not exists.add(record.id)):
				continue
			record.status = general.ErrorCode.DUPLICATE.value

	class Record:

		def __init__(
			self,
			id        : str,
			url       : str,
			method    : str,
			headers   : list[str],
			cookies   : list[str],
			body      : str,
			user_agent: str,
			proxy     : str,
			engine    : general.Engine,
			repeat    : int
		):
			"""
			Class for storing test details.
			"""
			self.id              : str                  = id
			self.url             : str                  = url
			self.method          : str                  = method
			self.headers         : list[str]            = headers
			self.cookies         : list[str]            = cookies
			self.body            : str                  = body
			self.user_agent      : str                  = user_agent
			self.proxy           : str                  = proxy
			self.engine          : general.Engine       = engine
			self.repeat          : int                  = repeat
			self.command         : str                  = self.__build_command()
			self.status          : int                  = general.ErrorCode.UNTESTED.value
			self.length          : int                  = 0
			self.response        : str                  = ""
			self.response_headers: str | dict[str, str] = "" if engine in [general.Engine.PYCURL] else {}
			self.error           : str                  = ""

		def update_id(self):
			"""
			Update the ID after a successful HTTP request.
			"""
			self.id = f"{self.status}-{self.length}-{self.id}"

		def is_valid(self):
			"""
			Check if the HTTP response status code is valid.
			"""
			return bool(general.StatusCode.from_status_code(self.status))

		def to_result(self):
			"""
			Serialize the test record to a JSON-compatible dictionary, excluding certain attributes.
			"""
			return self.__remove(["proxy", "engine", "repeat", "response", "response_headers", "error"])

		def to_test(self):
			"""
			Serialize the test record to a JSON-compatible dictionary, excluding certain attributes.
			"""
			return self.__remove(["proxy", "status", "length", "response", "response_headers", "error"])

		def __remove(self, attributes: list[str]):
			"""
			Serialize the test record to a JSON-compatible dictionary and exclude the specified attributes.
			"""
			tmp = self.__dict__
			for attribute in attributes:
				tmp.pop(attribute, None)
			return tmp

		def __build_command(self):
			"""
			Build a cURL command.
			"""
			tmp = ["curl", "--path-as-is", "-iskL"]
			# --------------------------------
			if self.engine in [general.Engine.HTTP_CLIENT]:
				tmp.append("--http1.0")
			# --------------------------------
			"""
			NOTE: These options only make the entire command look messy and are unnecessary when double-checking the results.
			tmp.extend([
				f"--max-redirs {max_redirects}",
				f"--connect-timeout {connect_timeout}",
				f"-m {read_timeout}"
			])
			"""
			# --------------------------------
			if self.proxy:
				tmp.append(set_opt(self.proxy, "-x"))
			if self.user_agent:
				tmp.append(set_opt(self.user_agent, "-A"))
			for header in self.headers:
				tmp.append(set_opt(header, "-H"))
			for cookie in self.cookies:
				tmp.append(set_opt(cookie, "-b"))
			if self.body:
				tmp.append(set_opt(self.body, "-d"))
			if self.method:
				tmp.append(set_opt(self.method, "-X"))
			if self.url:
				tmp.append(set_opt(self.url))
			# --------------------------------
			tmp = (" ").join(tmp)
			return tmp
