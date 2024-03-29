# Cryptonice
_Cryptonice_ collects data on a given domain and performs a series of tests to check TLS configuration and supporting protocols such as HTTP2 and DNS. It makes heavy use of open source code and libraries, including the [**SSLyze**](https://github.com/nabla-c0d3/sslyze) library for TLS testing, [**JARM**](https://github.com/salesforce/jarm) code for TLS fingerprinting and [**Wappalyzer**](https://github.com/AliasIO/Wappalyzer) code for server components checks.

Cryptonice is currently supported under Python 3.8 and later on the following platforms:

- **Windows**
- **Mac OS**
- **Ubuntu 20.04**
- **CentOS 8** (other Linux distros coming soon).

### Docker

A Linux compatible **Docker** container is also now available for those that prefer not to rely on installations of Python or any dependencies. With Docker already installed, first pull down the image:

`docker pull f5labs/cryptonice`

To run from the container, use the following command:

`docker run --rm -it f5labs/cryptonice www.f5.com`

If you want to output the JSON results to a folder on your local machine you must tell Docker to map a local path to a path within the container. The following example maps a folder in C:\Scratch to a new folder called /results within the container)::

`docker run --rm -it --volume //c/scratch:/results f5labs/cryptonice www.f5.com --json_out --json_path /results`

Once the scan is complete you should find the resulting www.f5.com.json file in your C:\Scratch folder.



For detailed and up to date documentation, check out our ReadTheDocs pages:

https://cryptonice.readthedocs.io/


### Installation

The easiest way to get started is by using PIP to install Cryptonice:

`pip install cryptonice`

[![asciicast](https://asciinema.org/a/354489.svg)](https://asciinema.org/a/354489?speed=3&autoplay=1)


### User Guide

_cryptonice_ requires a domain name (such as www.github.com).

`cryptonice www.github.com`

Providing only a domain name and no other command line input will result in the following default dictionary of commands being run.

    {
	    "id": "default",
	    "port": 443,
	    "scans": ["TLS", "HTTP", "HTTP2", "DNS", "JARM"],
	    "tls_params": ["certificate_information", "ssl_2_0_cipher_suites", "ssl_3_0_cipher_suites","tls_1_0_cipher_suites", "tls_1_1_cipher_suites", "tls_1_2_cipher_suites","tls_1_3_cipher_suites", "http_headers"],
	    "http_body": false,
	    "force_redirect": true,
	    "print_out": true,
	    "generate_json": true,
	    "targets": ["www.github.com"]
    }

The user can also choose to specify custom commands. Each custom command must be preceded with the name of the option (ex: to specify the scans TLS and HTTP to run, the user must add _--scans TLS HTTP_ to the command line parameters)
- _--PORT_: port to perform the scan on (default = 443)
- _--SCANS_: scans to perform
    - _TLS_ scan, _HTTP_ headers, _HTTP2_ check, _DNS_ data
- _--TLS_PARAMETERS_: TLS specific scans to perform (should be listed as specified below, with no commas between options):
    - all, no_vuln_tests, certificate_info, ssl_2_0_cipher_suites, ssl_3_0_cipher_suites, tls_1_0_cipher_suites,
      tls_1_1_cipher_suites, tls_1_2_cipher_suites, tls_1_3_cipher_suites, tls_compression,
      tls_1_3_early_data, openssl_ccs_injection, heartbleed, robot, tls_fallback_scsv,
      session_renegotiation, session_resumption, session_resumption_rate, http_headers
    - **all** results in all commands being run, **no_vuln_tests** results in certificate_info, http_headers and the cipher_suites commands being run.
    - More information on each of these scan options can be found at: https://nabla-c0d3.github.io/sslyze/documentation/available-scan-commands.html
- _--HTTP_BODY_: Y/y or N/n - sets a Boolean variable to include or exclude HTTP pages information
- _--FORCE_REDIRECTS_: Y/y or N/n - sets a Boolean variable to check for automatic redirects from port 80 to 443 in a TLS scan (default = Y)
- _--PRINT_OUT_: Y/y or N/n - sets a Boolean variable to print scan results to console (default = Y)
- _--JSON_OUT_: Y/y or N/n - sets a Boolean variable to print scan results to JSON output file (default = Y)

[![asciicast](https://asciinema.org/a/354498.svg)](https://asciinema.org/a/354498)

### Output
_cryptonice_ generates a JSON output file with the information requested by the input parameters. Output files will be named after the domain name and port provided (ex: target = www.github.com, port = 443, output = www.github.com-443.json)


### Utilizing the library in your own code
_cryptonice_ can be used within other projects as well. An example of this functionality can be found in the simple sample_script.py file. In that short script, the program input is a JSON file (sample_scan.json also provided) with the required commands. The data is read into a dictionary and sent to the scanner_driver function in cryptonice/scanner. Individual modules can also be called from outside functions, and will return a dictionary of the results. Further information on function parameters can be found in the code comments for each function.


### Limitations
This code does not currently have the capability to scan a server based on an IP address and an SNI. Instead, the user must supply a hostname and internally the code will do a DNS resolution. This may lead to discrepancies in the IP address scanned in the TLS portions and the HTTP headers section. Certain domain names may also result in only one certificate being returned. The issue currently persists in the sslyze API where we get the certificate information, and we are working to find a solution.
