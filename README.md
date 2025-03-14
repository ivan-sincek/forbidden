# Forbidden

Bypass 4xx HTTP response status codes and more.

The tool is based on `Python Requests`, `PycURL`, and `HTTP Client`.

The stress testing tool was inspired by this infosec [write-up](https://amineaboud.medium.com/story-of-a-weird-vulnerability-i-found-on-facebook-fc0875eb5125).

Tested on Kali Linux v2024.2 (64-bit).

Made for educational purposes. I hope it will help!

**Future plans:**

* Add the `silent` option to suppress console output.
* Add the `no color` option to disable colored console output.
* Add tests for `hop-by-hop` HTTP request headers.
* Add tests for the `User-Agent` HTTP request header.
* Add tests for HTTP cookies.
* Add tests for HTTP smuggling.
* Add tests for CRLF.
* Add tests for Log4j.
* Add tests for AWS metadata SSRF.

## Table of Contents

* [How to Install](#how-to-install)
    * [Install PycURL](#install-pycurl)
    * [Standard Install](#standard-install)
    * [Build and Install From the Source](#build-and-install-from-the-source)
* [How to Use](#how-to-use)
* [Tests](#tests)
    * [HTTP Methods](#http-methods)
    * [HTTP Request Headers](#http-request-headers)
* [Results](#results)
* [Usage](#usage)
* [Images](#images)

## How to Install

### Install PycURL

On Kali Linux, this should work without issues; otherwise, run:

```bash
apt-get -y install libcurl4-gnutls-dev librtmp-dev

pip3 install --upgrade pycurl
```

---

PycURL on Windows OS is not supported.

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

Alternatively, install using [Homebrew](https://formulae.brew.sh/formula/forbidden) (not maintained by me):

```fundamental
brew install forbidden
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

python3 -m pip install dist/forbidden-13.1-py3-none-any.whl
```

## How to Use

Bypass `403 Forbidden` HTTP response status code:

```fundamental
forbidden -u https://example.com/admin -t protocols,methods,uploads,overrides,headers,paths-ram,encodings -f GET -l initial,path -o forbidden_403_results.json
```

Bypass `403 Forbidden` HTTP response status code with stress testing:

```fundamental
mkdir stresser_403_results

stresser -u https://example.com/admin -r 1000 -th 200 -f GET -l initial -dir stresser_403_results -o stresser_403_results.json
```

Bypass `401 Unauthorized` HTTP response status code:

```fundamental
forbidden -u https://example.com/admin -t auths -f GET -l initial -o forbidden_401_results.json
```

Test for open redirects and broken URL parsers, i.e., test for out-of-band (OOB) interactions:

```fundamental
forbidden -u https://example.com/admin -t redirects,parsers -f GET -l initial -e xyz.interact.sh -o forbidden_oob_results.json
```

## Tests

**`protocols`**

* Test HTTP and HTTPS protocols using an IP address and domain name.
* Test an HTTP/1.0 protocol downgrade without the `Host` HTTP request header, using an IP address and domain name.

**`methods`**

* Test the allowed HTTP methods, also using the `Content-Length: 0` HTTP request header.
* Test Cross-Site Tracing (XST) using the HTTP TRACE and TRACK methods.

**`uploads`**

* Test a text file upload recursively for each directory in the URL path using the HTTP PUT method.

**`overrides`**

* Test HTTP method overrides using URL query string parameters, HTTP request headers, and HTTP request bodies.
* Test URL scheme overrides using HTTP request headers, from HTTPS to HTTP and from HTTP to HTTPS.
* Test port overrides using HTTP request headers.
* Test HTTP host overrides using HTTP request headers, also using two `Host` HTTP request headers.
* Test URL path overrides using HTTP request headers with relative URL paths, using the following URLs: an accessible URL, root URL, and full URL.

**`headers`**

* Test HTTP request headers with IP addresses, comma-separated IP addresses, domain names, root URLs, full URLs, and more.

**`values`**

* Test HTTP request headers with user-supplied IP addresses, domain names, root URLs, and full URLs.

**`paths`**

* Test URL path bypasses.

**`encodings`**

* Test URL host and path transformations and encodings.

**`auths`**

* Test basic authentication/authorization using HTTP request headers with null values and predefined Base64 encoded credentials.
* Test bearer authentication/authorization using HTTP request headers with null values, malformed JWTs, and predefined JWTs.

**`redirects`**

* Test open redirects using HTTP request headers with redirect IP addresses, domain names, root URLs, and full URLs.

**`parsers`**

* Test broken URL parsers using HTTP request headers with broken IP addresses, domain names, root URLs, and full URLs.

---

If you're interested in more details, see:

* [/src/forbidden/utils/forbidden.py](https://github.com/ivan-sincek/forbidden/blob/main/src/forbidden/utils/forbidden.py#L601)
* [/src/forbidden/utils/test.py](https://github.com/ivan-sincek/forbidden/blob/main/src/forbidden/utils/test.py)
* [/src/forbidden/utils/value.py](https://github.com/ivan-sincek/forbidden/blob/main/src/forbidden/utils/value.py)

---

**Remarks:**

* All the tests are based on public infosec and bug bounty write-ups.
* Some of the tests overlap; however, a `unique filter` is applied before anything is sent.
* All the HTTP request headers, URL query string parameters, etc., were validated based on official documentation.
* By default, both `Forbidden` and `Stresser` use the `Python Requests` engine.
* Testing the HTTP/1.0 protocol downgrade without the `Host` HTTP request header is locked to the `HTTP Client` engine. Additionally, the provided cURL command will not work properly because cURL does not allow removing the `Host` HTTP request header.
* Testing the HTTP host override using two `Host` HTTP request headers is locked to the `Python Requests` engine. Additionally, the provided cURL command will not work properly because cURL does not allow using two `Host` HTTP request headers.
* Testing URL host and path transformations and encodings is locked to the `PycURL` engine.
* Some web proxies might `normalize` URLs (e.g., when testing `encodings`), modify HTTP requests, or drop HTTP requests entirely.
* Some websites might require a valid or very specific `User-Agent` HTTP request header.
* Cross-Site Tracing (XST) is no longer considered a vulnerability.
* Beware of `rate limiting` and other similar anti-bot protections; take some time before running the tool again on the same domain.

### HTTP Methods

_This is just a quick overview of what is used, but not how it is used._

```fundamental
ACL
ARBITRARY
BASELINE-CONTROL
BIND
CHECKIN
CHECKOUT
CONNECT
COPY
DELETE
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

### HTTP Request Headers

_This is just a quick overview of what is used, but not how it is used._

```fundamental
19-Profile
Accept
Base-URL
CF-Connecting-IP
Client-IP
Cluster-Client-IP
Destination
Forwarded-For
Forwarded-For-IP
From
Front-End-HTTPS
Host
Incap-Client-IP
Origin
Profile
Proxy
Proxy-Client-IP
Redirect
Referer
Remote-Addr
Request-URI
True-Client-IP
URI
URL
WAP-Profile
WL-Proxy-Client-IP
X-Client-IP
X-Cluster-Client-IP
X-Forward
X-Forward-For
X-Forwarded
X-Forwarded-By
X-Forwarded-For
X-Forwarded-For-IP
X-Forwarded-For-Original
X-Forwarded-Host
X-Forwarded-Path
X-Forwarded-Port
X-Forwarded-Proto
X-Forwarded-Protocol
X-Forwarded-SSL
X-Forwarded-Scheme
X-Forwarded-Server
X-HTTP-DestinationURL
X-HTTP-Host-Override
X-HTTP-Method
X-HTTP-Method-Override
X-Host
X-Host-Override
X-Method
X-Method-Override
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
X-Rewrite-URL
X-Scheme
X-Server-IP
X-True-Client-IP
X-True-IP
X-URL-Scheme
X-Wap-Profile
```

## Results

**Remarks:**

* Results will be sorted by HTTP response status code `ascending`, HTTP response body length `descending`, and test ID `ascending`.
* By default, only `2xx` and `3xx` HTTP response status codes are included in the results and shown in the console output.
* The `length` attribute in the results refers to the HTTP response body length.
* To manually filter out `false positive` results, for each unique HTTP response content length, run the provided cURL command and check if the HTTP response results in bypass; if not, simply ignore all the results with the same content length.

```json
[
   {
      "id":"595-HOST-OVERRIDES-1",
      "url":"https://example.com:443/admin",
      "method":"GET",
      "headers":[
         "Host: 127.0.0.1"
      ],
      "cookies":[],
      "body":"",
      "user_agent":"Forbidden/13.1",
      "command":"curl --path-as-is -iskL -A 'Forbidden/13.1' -H 'Host: 127.0.0.1' -X 'GET' 'https://example.com:443/admin'",
      "status":200,
      "length":14301
   },
   {
      "id":"596-HOST-OVERRIDES-1",
      "url":"https://example.com:443/admin",
      "method":"GET",
      "headers":[
         "Host: 127.0.0.1:443"
      ],
      "cookies":[],
      "body":"",
      "user_agent":"Forbidden/13.1",
      "command":"curl --path-as-is -iskL -A 'Forbidden/13.1' -H 'Host: 127.0.0.1:443' -X 'GET' 'https://example.com:443/admin'",
      "status":200,
      "length":14301
   }
]
```

## Usage

```fundamental
Forbidden v13.1 ( github.com/ivan-sincek/forbidden )

Usage:   forbidden -u url                       -t tests [-f force] [-o out         ]
Example: forbidden -u https://example.com/admin -t all   [-f GET  ] [-o results.json]

DESCRIPTION
    Bypass 4xx HTTP response status codes and more
URL
    Inaccessible URL
    -u, --url = https://example.com/admin | etc.
IGNORE PARAMETERS
    Ignore URL query string and fragment
    -ip, --ignore-parameters
IGNORE REQUESTS
    Where applicable, use PycURL instead of the default Python Requests engine
    -ir, --ignore-requests
TESTS
    Tests to run
    Specify '[ip-|host-|url-]values' to test HTTP request headers using only user-supplied values passed with the '-v' option
    Specify 'paths-ram' to use the battering ram attack or 'paths' to use the default cluster bomb attack
    Use comma-separated values
    -t, --tests = protocols | methods | uploads | [method-|scheme-|port-|host-|path-]overrides | headers | [ip-|host-|url-]values | paths[-ram] | encodings | [basic-|bearer-]auths | redirects | parsers | all
VALUES
    File containing HTTP request header values or a single value, e.g., internal IP, etc.
    Tests: all-values
    -v, --values = values.txt | 10.10.15.20 | example.local | https://example.local | etc.
FORCE
    Force an HTTP method for all non-specific tests
    -f, --force = GET | POST | CUSTOM | etc.
PATH
    Accessible URL path to test URL path overrides
    Tests: path-overrides
    Default: /robots.txt, /index.html, /sitemap.xml, /README.txt
    -p, --path = /home | etc.
EVIL
    Evil URL or collaborator service
    Tests: host-overrides, headers, bearer-auths, redirects, parsers
    Default: https://github.com
    -e, --evil = https://xyz.interact.sh | https://xyz.burpcollaborator.net | etc.
HEADER
    Any number of extra HTTP request headers
    Extra HTTP request headers will not override test-specific HTTP request headers
    Semi-colon in, e.g., 'Content-Type;' will expand to an empty HTTP request header
    -H, --header = "Authorization: Bearer ey..." | Content-Type; | etc.
COOKIE
    Any number of extra HTTP cookies
    Extra HTTP cookies will not override test-specific HTTP cookies
    -b, --cookie = PHPSESSIONID=3301 | etc.
IGNORE
    RegEx to filter out false positive 200 OK results
    -i, --ignore = Inaccessible | "Access Denied" | "Error: .+" | etc.
CONTENT LENGTHS
    HTTP response content lengths to filter out false positive 200 OK results
    Specify 'initial' to ignore the content length of the initial HTTP response
    Specify 'path' to ignore the content length of the accessible URL's response
    Use comma-separated values
    -l, --content-lengths = 12 | initial | path | etc.
REQUEST TIMEOUT
    Request timeout in seconds
    Default: 60
    -rt, --request-timeout = 30 | 90 | etc.
THREADS
    Number of parallel threads to run
    Default: 5
    -th, --threads = 20 | etc.
SLEEP
    Sleep time in milliseconds before sending an HTTP request
    Intended for a single-thread use
    -s, --sleep = 500 | etc.
USER AGENT
    User agent to use
    Default: Forbidden/13.1
    -a, --user-agent = random[-all] | curl/3.30.1 | etc.
PROXY
    Web proxy to use
    -x, --proxy = http://127.0.0.1:8080 | etc.
HTTP RESPONSE STATUS CODES
    Include only specific HTTP response status codes in the results
    Default: 2xx, 3xx
    Use comma-separated values
    -sc, --status-codes = 1xx | 2xx | 3xx | 4xx | 5xx | all
SHOW TABLE
    Display the results in a table format instead of JSON format
    Intended for use on a wide screen
    -st, --show-table
OUT
    Output file
    -o, --out = results.json | etc.
DUMP
    Dump all the test records into the output file without running any
    -dmp, --dump
DEBUG
    Enable debug output
    -dbg, --debug
```

```fundamental
Stresser v13.1 ( github.com/ivan-sincek/forbidden )

Usage:   stresser -u url                       -r repeat -th threads -dir directory [-f force] [-o out         ]
Example: stresser -u https://example.com/admin -r 1000   -th 200     -dir results   [-f GET  ] [-o results.json]

DESCRIPTION
    Bypass 4xx HTTP response status codes with stress testing
URL
    Inaccessible URL
    -u, --url = https://example.com/admin | etc.
IGNORE PARAMETERS
    Ignore URL query string and fragment
    -ip, --ignore-parameters
IGNORE REQUESTS
    Where applicable, use PycURL instead of the default Python Requests engine
    -ir, --ignore-requests
FORCE
    Force an HTTP method for all non-specific tests
    -f, --force = GET | POST | CUSTOM | etc.
HEADER
    Any number of extra HTTP request headers
    Extra HTTP request headers will not override test-specific HTTP request headers
    Semi-colon in, e.g., 'Content-Type;' will expand to an empty HTTP request header
    -H, --header = "Authorization: Bearer ey..." | Content-Type; | etc.
COOKIE
    Any number of extra HTTP cookies
    Extra HTTP cookies will not override test-specific HTTP cookies
    -b, --cookie = PHPSESSIONID=3301 | etc.
IGNORE
    RegEx to filter out false positive 200 OK results
    -i, --ignore = Inaccessible | "Access Denied" | "Error: .+" | etc.
CONTENT LENGTHS
    HTTP response content lengths to filter out false positive 200 OK results
    Specify 'initial' to ignore the content length of the initial HTTP response
    Use comma-separated values
    -l, --content-lengths = 12 | initial | etc.
REQUEST TIMEOUT
    Request timeout in seconds
    Default: 60
    -rt, --request-timeout = 30 | 90 | etc.
REPEAT
    Number of HTTP requests per test
    -r, --repeat = 1000 | etc.
THREADS
    Number of parallel threads to run
    -th, --threads = 20 | etc.
USER AGENT
    User agent to use
    Default: Stresser/13.1
    -a, --user-agent = random[-all] | curl/3.30.1 | etc.
PROXY
    Web proxy to use
    -x, --proxy = http://127.0.0.1:8080 | etc.
HTTP RESPONSE STATUS CODES
    Include only specific HTTP response status codes in the results
    Default: 2xx, 3xx
    Use comma-separated values
    -sc, --status-codes = 1xx | 2xx | 3xx | 4xx | 5xx | all
SHOW TABLE
    Display the results in a table format instead of JSON format
    Intended for use on a wide screen
    -st, --show-table
OUT
    Output file
    -o, --out = results.json | etc.
DIRECTORY
    Output directory
    All valid and unique HTTP responses will be saved in this directory
    -dir, --directory = results | etc.
DUMP
    Dump all the test records into the output file without running any
    -dmp, --dump
DEBUG
    Enable debug output
    -dbg, --debug
```

## Images

<p align="center"><img src="https://github.com/ivan-sincek/forbidden/blob/main/img/real_example.png" alt="Real Example"></p>

<p align="center">Figure 1 - Real Example</p>

<p align="center"><img src="https://github.com/ivan-sincek/forbidden/blob/main/img/simple_example.png" alt="Simple Example"></p>

<p align="center">Figure 2 - Simple Example</p>

<p align="center"><img src="https://github.com/ivan-sincek/forbidden/blob/main/img/simple_example_table_output.png" alt="Simple Example (Table Output)"></p>

<p align="center">Figure 3 - Simple Example (Table Output)</p>
