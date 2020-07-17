Command Line
============

The default command for cryptonice is
::
    cryptonice <domain_name>

This results in the following commands being run
::
    {
        "id": "default",
        "port": 443,
        "scans": ["TLS", "HTTP", "HTTP2", "DNS"],
        "tls_params": ["certificate_information", "ssl_2_0_cipher_suites", "ssl_3_0_cipher_suites","tls_1_0_cipher_suites", "tls_1_1_cipher_suites", "tls_1_2_cipher_suites","tls_1_3_cipher_suites", "http_headers"],
        "http_body": false,
        "force_redirect": true,
        "print_out": true,
        "generate_json": true,
        "targets": [<domain_name>]
    }

The user can choose to specify custom commands. Each custom command must be preceded with the name of the option (ex: to specify the scans TLS and HTTP to run, the user must add --scans TLS HTTP to the command line parameters)

  * --PORT: port to perform the scan on (default = 443)

  * --SCANS: scans to perform

     * TLS scan, HTTP headers, HTTP2 check, DNS data (default = None)

  * --TLS_PARAMETERS: TLS specific scans to perform (should be listed as specified below, with no commas between options):

     * all, no_vuln_tests, certificate_info, ssl_2_0_cipher_suites, ssl_3_0_cipher_suites, tls_1_0_cipher_suites, tls_1_1_cipher_suites, tls_1_2_cipher_suites, tls_1_3_cipher_suites, tls_compression, tls_1_3_early_data, openssl_ccs_injection, heartbleed, robot, tls_fallback_scsv, session_renegotiation, session_resumption, session_resumption_rate, http_headers

     * all results in all commands being run, no_vuln_tests results in certificate_info, http_headers and the cipher_suites commands being run.

     * More information on each of these scan options can be found at: https://nabla-c0d3.github.io/sslyze/documentation/available-scan-commands.html

  * --HTTP_BODY: Y/y or N/n - sets a Boolean variable to include or exclude HTTP pages information

  * --FORCE_REDIRECTS: Y/y or N/n - sets a Boolean variable to check for automatic redirects from port 80 to 443 in a TLS scan (default = Y)

  * --PRINT_OUT: Y/y or N/n - sets a Boolean variable to print scan results to console (default = Y)

  * --JSON_OUT: Y/y or N/n - sets a Boolean variable to print scan results to JSON output file (default = Y)
