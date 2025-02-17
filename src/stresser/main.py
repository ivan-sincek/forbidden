#!/usr/bin/env python3

from .utils import config, file, general, stresser, validate

import datetime

# ----------------------------------------

class Stopwatch:

	def __init__(self):
		self.__start = datetime.datetime.now()

	def stop(self):
		self.__end = datetime.datetime.now()
		print(f"Script has finished in {self.__end - self.__start}")

stopwatch = Stopwatch()

# ----------------------------------------

def main():
	success, args = validate.Validate().validate_args()
	if success:
		config.banner()
		tool = stresser.Stresser(
			args.url,
			args.ignore_parameters,
			args.ignore_requests,
			args.force,
			args.header,
			args.cookie,
			args.ignore,
			args.content_lengths,
			args.request_timeout,
			args.repeat,
			args.user_agent,
			args.proxy,
			args.status_codes,
			args.directory,
			args.debug
		)
		results = tool.run(args.threads, args.show_table, args.dump)
		stopwatch.stop()
		if results and args.out:
			file.overwrite(general.jdump(results), args.out)

if __name__ == "__main__":
	main()
