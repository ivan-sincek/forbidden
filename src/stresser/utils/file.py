#!/usr/bin/env python3

from . import record

import os

def write_result_silent(record: record.Records.Record, directory = ""):
	"""
	Silently write a result to an output file.
	"""
	try:
		file = os.path.join(directory, f"{record.id}.txt")
		if not os.path.exists(file):
			open(file, "w").write(record.response)
	except Exception:
		pass

def overwrite(text: str, out: str):
	"""
	Write a text to an output file.\n
	If the output file exists, prompt to overwrite it.
	"""
	confirm = "yes"
	if os.path.isfile(out):
		print(f"'{out}' already exists")
		confirm = input("Overwrite the output file (yes): ")
	if confirm.lower() in ["yes", "y"]:
		try:
			open(out, "w").write(text)
			print(f"Results have been saved to '{out}'")
		except FileNotFoundError:
			print(f"Cannot save the results to '{out}'")
