# cryptonice
Built using the sslyze API and ssl, http-client and dns libraries, _cryptonice_ collects data on a given domain and performs a series of tests to check TLS configuration and supporting protocols such as HTTP2 and DNS. 

### User Guide

_cryptonice_ requires a domain name (like www.github.com) and either a _DEFAULT_ or _CUSTOM_ tag to run. 

_DEFAULT_ will result in the following dictionary of commands being run.
   
    {
	    "id": "test.py",
	    "port": 443,
	    "scans": ["TLS", "HTTP", "DNS"],
	    "tls_params": ["certificate_information", "ssl_2_0_cipher_suites", "ssl_3_0_cipher_suites","tls_1_0_cipher_suites", "tls_1_1_cipher_suites", "tls_1_2_cipher_suites","tls_1_3_cipher_suites", "http_headers"],
	    "http_body": false,
	    "force_redirect": true,
	    "print_out": true,
	    "targets": ["www.github.com"]
    }

_CUSTOM_ allows the user to further specify the commands to their liking. The optional commands are:
- _--PORT_: port to perform the scan on (default = 443)
- _--SCANS_: scans to perform (options: "TLS" scan, "HTTP" headers, "HTTP2" check, "DNS" data)
- _--TLS_PARAMETERS_: TLS specific scans to perform:
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

### Output
_cryptonice_ generates a JSON output file with the information requested by the input parameters. Output files will be named after the domain name and port provided (ex: target = www.github.com, port = 443, output = www.github.com-443.json)

### Limitations
This code does not currently have the capability to scan a server based on an IP address and an SNI. Instead, the user must supply a hostname and internally the code will do a DNS resolution. This may lead to discrepancies in the IP address scanned in the TLS portions and the HTTP headers section. 