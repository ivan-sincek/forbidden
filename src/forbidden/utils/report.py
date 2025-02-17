#!/usr/bin/env python3

from . import general, record

import tabulate, typing

class Report:

	def __init__(self, collection: record.Records, status_codes: list[general.StatusCode]):
		"""
		Class for storing and managing the results.
		"""
		self.__valid        = sorted(collection.get_valid(), key = lambda record: (record.status, -record.length, record.id_int))
		self.__statistics   = self.__get_statistics(collection.get())
		self.__status_codes = status_codes

	# ------------------------------------

	def __show_json(self) -> list[dict[str, typing.Any]]:
		"""
		Show the test records in a JSON format and return them as a JSON-compatible list.
		"""
		tmp = []
		for record in self.__valid:
			if general.StatusCode.from_status_code(record.status) in self.__status_codes:
				result = record.to_result()
				print(general.color(general.jdump(result), general.StatusCode.get_color_name(record.status)))
				tmp.append(result)
		return tmp

	def __show_table(self) -> list[dict[str, typing.Any]]:
		"""
		Show the test records in a table format and return them as a JSON-compatible list.
		"""
		tmp = []
		table = []
		for record in self.__valid:
			if general.StatusCode.from_status_code(record.status) in self.__status_codes:
				tmp.append(record.to_result())
				table.append(general.color_multiple([getattr(record, attr) for attr in ["id", "status", "length", "command"]], general.StatusCode.get_color_name(record.status)))
		if table:
			print(tabulate.tabulate(table, tablefmt = "plain", colalign = ("right", "right", "right", "left")))
		return tmp

	def show(self, show_table = False):
		"""
		Show the test records in a JSON or table format and return them as a JSON-compatible list.
		"""
		return self.__show_table() if show_table else self.__show_json()

	# ------------------------------------

	def __get_statistics(self, records: list[record.Records.Record]) -> dict[int, int]:
		"""
		Get HTTP response status code statistics.
		"""
		tmp = {}
		for record in records:
			tmp[record.status] = tmp.get(record.status, 0) + 1

		def __sort_by_status_code(status_code: int):
			if status_code in general.ErrorCode.all():
				return (1, status_code)
			else:
				return (0, status_code)

		return dict(sorted(tmp.items(), key = lambda status_code: __sort_by_status_code(status_code[0])))

	def show_statistics(self):
		"""
		Show the HTTP response status code statistics in a table format.
		"""
		table = []
		for code, count in self.__statistics.items():
			table.append(general.color_multiple([general.ErrorCode.get_error_name(code), count], general.StatusCode.get_color_name(code)))
		if table:
			print(tabulate.tabulate(table, ["Status Code", "Count"], tablefmt = "outline", colalign = ("left", "right")))
