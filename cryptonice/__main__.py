from cryptonice.scanner import scanner_driver
from cryptonice.__init__ import __version__
import argparse

cryptonice_version=__version__

default_dict = {'id': 'default',
                'port': 443,
                'scans': ['TLS', 'HTTP', 'HTTP2', 'DNS', 'JARM'],
                'tls_params': ["certificate_info", "ssl_2_0_cipher_suites", "ssl_3_0_cipher_suites",
                               "tls_1_0_cipher_suites", "tls_1_1_cipher_suites", "tls_1_2_cipher_suites",
                               "tls_1_3_cipher_suites", "http_headers"],
                'http_body': False,
                'no_console': False,
                'no_redirect': False,
                'generate_json': False
                }

all_tls_options = ['certificate_info', 'ssl_2_0_cipher_suites', 'ssl_3_0_cipher_suites', 'tls_1_0_cipher_suites',
                   'tls_1_1_cipher_suites', 'tls_1_2_cipher_suites', 'tls_1_3_cipher_suites', 'tls_compression',
                   'tls_1_3_early_data', 'openssl_ccs_injection', 'heartbleed', 'robot', 'tls_fallback_scsv',
                   'session_renegotiation', 'session_resumption', 'session_resumption_rate', 'http_headers']

no_vuln_tests = ['certificate_info', 'ssl_2_0_cipher_suites', 'ssl_3_0_cipher_suites', 'tls_1_0_cipher_suites',
                 'tls_1_1_cipher_suites', 'tls_1_2_cipher_suites', 'tls_1_3_cipher_suites', 'http_headers']


def main():
    parser = argparse.ArgumentParser(description="Supply commands to Cryptonice", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("domain", nargs='+', help="Domain name to scan", type=str, default="")
    parser.add_argument("--port", help="Port to perform scans on", type=int, default=443)
    parser.add_argument("--scans", nargs='+', help="Scans to run as a space delimted string, selecting from: TLS HTTP HTTP2 DNS JARM", default="dns tls http http2 jarm")
    parser.add_argument("--tls", nargs='+', help="all, no_vuln_tests, certificate_info, "
                                                 "ssl_2_0_cipher_suites, ssl_3_0_cipher_suites, tls_1_0_cipher_suites, "
                                                 "tls_1_1_cipher_suites, tls_1_2_cipher_suites, tls_1_3_cipher_suites, "
                                                 "tls_compression, tls_1_3_early_data, openssl_ccs_injection, "
                                                 "heartbleed, robot, tls_fallback_scsv, session_renegotiation, "
                                                 "session_resumption, session_resumption_rate, http_headers", default="no_vuln_tests")
    parser.add_argument("--http_body", help="Include HTTP pages information in output", action='store_true')
    parser.add_argument("--no_redirect", help="Check for redirects from port 80 to 443 automatically", action='store_false')
    parser.add_argument("--no_console", help="Print output to console", action='store_false')
    parser.add_argument("--json_out", help="Write output to JSON file (True/False)", action='store_true')
    parser.add_argument("--json_path", help="Send JSON file(s) to specific directory", type=str, default="./")
    parser.add_argument("-v", "--version", help="Display version of Cryptonice", action='version', version=cryptonice_version)

    parser._positionals.title = 'Required'
    parser._optionals.title = 'Optional'

    args = parser.parse_args()

    domain_name = args.domain
    if domain_name == "":
        #parser.error('Please provide a domain name or IP address to scan')
        print('  Please provide a domain name or IP address to scan')
        print('  Use -h for help')
        quit()

    input_data = {}

    input_data.update({'id': 'default'})
    input_data.update({'cn_version': cryptonice_version})
    input_data.update({'port': args.port})

    tls_parameters = args.tls

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

    if not args.no_redirect:
        input_data.update({'force_redirect': False})
    else:
        input_data.update({'force_redirect': True})

    if not args.no_console:
        input_data.update({'print_out': False})
    else:
        input_data.update({'print_out': True})

    generate_json = False
    if args.json_out:
        generate_json = True

    input_data.update({'generate_json': generate_json})
    input_data.update({'json_path': args.json_path})

    input_data.update({'targets': domain_name})

    output_data, hostname = scanner_driver(input_data)
    if output_data is None and hostname is None:
        print('Error with input - scan was not completed')


if __name__ == "__main__":
    main()
