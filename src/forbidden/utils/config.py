#!/usr/bin/env python3

APP_VERSION = "v13.0"

USER_AGENT = "Forbidden/13.0"

def banner():
	"""
	Display the banner.
	"""
	print("#########################################################################")
	print("#                                                                       #")
	print("#                            Forbidden v13.0                            #")
	print("#                                 by Ivan Sincek                        #")
	print("#                                                                       #")
	print("# Bypass 4xx HTTP response status codes and more.                       #")
	print("# GitHub repository at github.com/ivan-sincek/forbidden.                #")
	print("#                                                                       #")
	print("#########################################################################")

# ----------------------------------------

ACCESSIBLE_PATHS = ["/robots.txt", "/index.html", "/sitemap.xml", "/README.txt"]

EVIL_URL = "https://github.com"
