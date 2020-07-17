from cryptonice.scanner import scanner_driver
import argparse

default_dict = {'id': 'default',
                'port': 443,
                'scans': ['TLS', 'HTTP', 'HTTP2', 'DNS'],
                'tls_params': ["certificate_info", "ssl_2_0_cipher_suites", "ssl_3_0_cipher_suites",
                               "tls_1_0_cipher_suites", "tls_1_1_cipher_suites", "tls_1_2_cipher_suites",
                               "tls_1_3_cipher_suites", "http_headers"],
                'http_body': False,
                'print_out': True,
                'generate_json': True,
                'force_redirect': True
                }

all_tls_options = ['certificate_info', 'ssl_2_0_cipher_suites', 'ssl_3_0_cipher_suites', 'tls_1_0_cipher_suites',
                   'tls_1_1_cipher_suites', 'tls_1_2_cipher_suites', 'tls_1_3_cipher_suites', 'tls_compression',
                   'tls_1_3_early_data', 'openssl_ccs_injection', 'heartbleed', 'robot', 'tls_fallback_scsv',
                   'session_renegotiation', 'session_resumption', 'session_resumption_rate', 'http_headers']

no_vuln_tests = ['certificate_info', 'ssl_2_0_cipher_suites', 'ssl_3_0_cipher_suites', 'tls_1_0_cipher_suites',
                 'tls_1_1_cipher_suites', 'tls_1_2_cipher_suites', 'tls_1_3_cipher_suites', 'http_headers']


def main():
    parser = argparse.ArgumentParser(description="Supply commands to f5labsscanner")
    parser.add_argument("domain", nargs='+', help="Domain name to scan", type=str)
    parser.add_argument("--port", help="port to perform scans on (TLS=443)", type=int)
    parser.add_argument("--scans", nargs='+', help="scans to run: TLS, HTTP, DNS, HTTP2")
    parser.add_argument("--tls_parameters", nargs='+',
                        help="parameters for TLS scan: all, no_vuln_tests, certificate_info, "
                             "ssl_2_0_cipher_suites, ssl_3_0_cipher_suites, tls_1_0_cipher_suites, "
                             "tls_1_1_cipher_suites, tls_1_2_cipher_suites, tls_1_3_cipher_suites, "
                             "tls_compression, tls_1_3_early_data, openssl_ccs_injection, "
                             "heartbleed, robot, tls_fallback_scsv, session_renegotiation, "
                             "session_resumption, session_resumption_rate, http_headers")
    parser.add_argument("--http_body", help="y/n: include HTTP pages information in output (default = N)")
    parser.add_argument("--force_redirect",
                        help="y/n: check for redirects from port 80 to 443 automatically (default = Y)")
    parser.add_argument("--print_out", help="y/n: print output to console (default = Y)")
    parser.add_argument("--json_out", help="y/n: send output to JSON file (default = Y)")

    args = parser.parse_args()
    domain_name = args.domain
    if not domain_name:
        parser.error('domain (like www.google.com or f5.com) is required')

    # if only domain name was supplied, run a default scan
    if not args.port and not args.scans and not args.tls_parameters and not args.http_body \
            and not args.force_redirect and not args.print_out and not args.json_out:
        input_data = default_dict
        input_data.update({'targets': domain_name})
        output_data, hostname = scanner_driver(input_data)
    else:
        input_data = {}
        input_data.update({'id': 'custom'})

        port = args.port
        if port is None:
            port = 443
        input_data.update({'port': port})

        tls_parameters = args.tls_parameters

        if not args.scans and tls_parameters:  # if user provided TLS parameters, perform TLS scan
            input_data.update({'scans': ["TLS"]})
        elif not args.scans:  # if nothing was provided, queue no scans
            input_data.update({'scans': []})
        else:  # queue scans provided in command line
            input_data.update({'scans': args.scans})

        if not tls_parameters:
            input_data.update({'tls_params': []})
        elif 'all' in tls_parameters:
            input_data.update({'tls_params': all_tls_options})
        elif 'no_vuln_tests' in tls_parameters:
            input_data.update({'tls_params': no_vuln_tests})
        else:
            input_data.update({'tls_params': tls_parameters})

        http_body = args.http_body
        if http_body == 'y' or http_body == 'Y':
            input_data.update({'http_body': True})
        else:
            input_data.update({'http_body': False})

        force_redirect = args.force_redirect
        if force_redirect == "N" or force_redirect == "n":
            input_data.update({'force_redirect': False})
        else:
            input_data.update({'force_redirect': True})

        print_to_console = True
        if args.print_out == "N" or args.print_out == "n":
            print_to_console = False
        input_data.update({'print_out': print_to_console})

        generate_json = True
        if args.json_out == "N" or args.json_out == "n":
            generate_json = False
        input_data.update({'generate_json': generate_json})

        input_data.update({'targets': domain_name})

        output_data, hostname = scanner_driver(input_data)
        if output_data is None and hostname is None:
            print('Error with input - scan was not completed')


if __name__ == "__main__":
    main()
