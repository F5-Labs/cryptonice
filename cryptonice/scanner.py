# cryptonice
# scanner.py

import json, socket, ipaddress

from cryptonice.modules.gettls import tls_scan
from cryptonice.modules.gethttp import get_http
from cryptonice.modules.getdns import get_dns
from cryptonice.modules.gethttp2 import check_http2
from cryptonice.checkport import port_open
from datetime import datetime

tls_command_list = {'certificate_info', 'ssl_2_0_cipher_suites', 'ssl_3_0_cipher_suites', 'tls_1_0_cipher_suites',
                    'tls_1_1_cipher_suites', 'tls_1_2_cipher_suites', 'tls_1_3_cipher_suites', 'tls_compression',
                    'tls_1_3_early_data', 'openssl_ccs_injection', 'heartbleed', 'robot', 'tls_fallback_scsv',
                    'session_renegotiation', 'session_resumption', 'session_resumption_rate', 'http_headers'}


def writeToJSONFile(path, filename, data):
    """
    Write contents of dictionary with hostname: certificate key-value pairs to a json file
    :param path: path to destination file
    :param filename: name of destination filegit ad
    :param data: dictionary with key value pairs
    :return: None
    """
    if "/" in filename:
        filename = filename.split("/", 1)[0]

    filePathNameWExt = './' + path + '/' + filename + '.json'
    with open(filePathNameWExt, 'w') as fp:
        json.dump(data, fp, default=print_errors)
    print(f'\nOutputting data to {filePathNameWExt}')


def print_errors(error):
    try:
        return error.__str__()
    except:
        return "Not JSON serializable"


def print_to_console(str_host, tls_data, http_data, http2_data, dns_data, b_httptohttps, force_redirect):
    print('\n')
    print('RESULTS')
    print('-------------------------------------')
    print(f'Hostname: {str_host}\n')

    if tls_data == "Port closed - no TLS data available":
        print('***TLS Results***')
        print(f'Port closed - no TLS data available')
    elif tls_data:
        print(f'Selected Cipher Suite: {tls_data.get("cipher_suite_supported")}')
        print(f'Selected TLS Version: {tls_data.get("highest_tls_version_supported")}')
        if isinstance(http2_data, str):
            print(http2_data)
        elif http2_data:
            print(f'HTTP/2 Supported {http2_data.get("http2")}')
        print('')

        try:
            if tls_data.get("ssl_2_0").get("accepted_ssl_2_0_cipher_suites"):
                print('SSL 2.0: Supported')
            else:
                print('SSL 2.0: Unsupported')
        except:
            pass
        try:
            if tls_data.get("ssl_3_0").get("accepted_ssl_3_0_cipher_suites"):
                print('SSL 3.0: Supported')
            else:
                print('SSL 3.0: Unsupported')
        except:
            pass
        try:
            if tls_data.get("tls_1_0").get("accepted_tls_1_0_cipher_suites"):
                print('TLS 1.0: Supported')
            else:
                print('TLS 1.0: Unsupported')
        except:
            pass
        try:
            if tls_data.get("tls_1_1").get("accepted_tls_1_1_cipher_suites"):
                print('TLS 1.1: Supported')
            else:
                print('TLS 1.1: Unsupported')
        except:
            pass
        try:
            if tls_data.get("tls_1_2").get("accepted_tls_1_2_cipher_suites"):
                print('TLS 1.2: Supported')
            else:
                print('TLS 1.2: Unsupported')
        except:
            pass
        try:
            tls_1_3_support = True if tls_data.get("tls_1_3").get("accepted_tls_1_3_cipher_suites") != [] else False
            early_data = tls_data.get("tests").get("accepts_early_data")
            if early_data is None:
                print(f'{"TLS 1.3: Supported" if tls_1_3_support else "TLS 1.3: Unsupported"}')
            elif tls_1_3_support and early_data:
                print(f'TLS 1.3: Supported (early data supported)')
            elif tls_1_3_support and not early_data:
                print(f'TLS 1.3: Supported (early data not supported)')
            elif not tls_1_3_support and early_data:
                print(f'TLS 1.3: Unsupported (early data supported)')
            else:
                print(f'TLS 1.3: Unsupported (early data not supported)')
        except:
            pass

    # Print HTTP Data
    if force_redirect:
        print(f'\nHTTP to HTTPS redirect: {True if b_httptohttps else False}')

    if http_data:
        try:
            strict_transport_security = http_data.get("Headers").get("Strict-Transport-Security")
            if strict_transport_security is not None:
                print(f'HTTP Strict Transport Security: True ({strict_transport_security})')
            else:
                print(f'HTTP Strict Transport Security: False')
        except:
            pass

        try:
            public_key_pins = http_data.get("Headers").get("Public-Key-Pins")
            if public_key_pins is not None:
                print(f'HTTP Public Key Pinning: True')
                for pin in public_key_pins:
                    print(f'\t{pin}')
            else:
                print(f'HTTP Public Key Pinning: False')
            print('')
        except:
            pass

        try:
            print(f'Secure Cookies: {True if http_data.get("Cookies") != "" else False}\n')
        except:
            pass

    print('CAA Restrictions:')
    try:
        if dns_data.get("DNS").get("CAA"):
            for record in dns_data.get("DNS").get("CAA"):
                print(f'\t{record}')
        else:
            print('None')
    except:
        print('Did not collect DNS data')

    # Print certificate data if it was collected
    try:
        cert_0 = tls_data.get("certificate_info").get("certificate_0")
        print(f'\nLEAF CERTIFICATE')
        print(f'Common Name:\t\t {cert_0.get("common_name")}')
        print(f'Public Key Algorithm:\t {cert_0.get("public_key_algorithm")}')
        print(f'Public Key Size:\t {cert_0.get("public_key_size")}')
        if cert_0.get("public_key_algorithm") == "EllipticCurvePublicKey":
            print(f'Curve Algorithm:\t {cert_0.get("curve_algorithm")}')
        print(f'Signature Algorithm:\t {cert_0.get("signature_algorithm")}')
        print('')

        print(f'Valid From:\t\t {cert_0.get("valid_from")}')
        print(f'Valid Until:\t\t {cert_0.get("valid_until")}')
        print(f'Certificate is valid:\t {True if cert_0.get("valid_from") < datetime.today().__str__() < cert_0.get("valid_until") else False}')
        print('')

        try:
            print(
                f'OCSP Response: {"SUCCESSFUL" if tls_data.get("certificate_info").get("ocsp_response") is not None else "UNSUCCESSFUL"}')
            print(
                f'Must Staple Extension: {True if tls_data.get("certificate_info").get("leaf_certificate_has_must_stable_extension") else False}')
            print(
                f'Extended Validation: {True if tls_data.get("certificate_info").get("leaf_certificate_is_ev") else False}')
        except:
            pass
        print('')

        print(f'Subject Alternative Names:')
        for name in cert_0.get("subject_alt_names"):
            print(f'\t {name}')
    except:
        pass


def scanner_driver(input_data):
    b_httptohttps = False
    job_id = input_data['id']
    port = input_data['port']
    if port is None:
        port = 443  # default to 443 if none is supplied in input file

    # Check to see if user has supplied an SNI. If so, this SNI will be used for all tests unless overriden by the
    # HTTP redirect checks
    try:
        host_sni = input_data['sni']
    except:
        host_sni = ""

    tls_data = {}
    http_data = {}
    dns_data = {}
    geolocation_data = {}
    http2_data = {}

    for hostname in input_data['targets']:  # host names to scan
        host_path = hostname  # all functions should use host_path for consistency
        if host_sni == "":
            host_sni = hostname
        ip_address = ""

        print(f'\nScanning {hostname} on port {port}...')

        start_time = datetime.today()  # added to scan metadata later
        scan_data = {}  # final dictionary with metadata and scan results
        metadata = {}  # track metadata
        metadata.update({'job_id': job_id})
        metadata.update({'hostname': hostname})
        metadata.update({'port': port})
        metadata.update({'node_name': socket.gethostname()})

        #########################################################################################################
        # We can also check DNS regardless of open ports since it's an independent protocol
        # At this point there should be no WWW. prefix or path, but it's a good idea to check and scrub it anyway

        # First check if our target is actually a valid IP address...
        # If it is, set the IP address to the 'hostname',
        # if not, perform a DNS lookup
        try:
            ipaddress.ip_address(hostname)
            # If we have a valid IP, skip the DNS lookup...
            ip_address = hostname
            print(f'{hostname} is already a valid IP')
        except:
            # Determine if we are only using DNS to get an IP address, or whether we should query for all records
            if 'DNS' in input_data['scans']:
                dns_data = get_dns(hostname, True)
            else:
                dns_data = get_dns(hostname, False)

            if dns_data:
                ip_address = dns_data.get('DNS').get('A')[0]  # get first IP in list
                print(f'{hostname} resolves to {ip_address}')
        #########################################################################################################

        str_host = hostname  # will allow data to be outputted even if port is closed
        # Now we begin the proper scans based on the port we've been asked to connect to
        target_portopen, target_tlsopen = port_open(ip_address, port)

        force_redirect = input_data['force_redirect']

        if target_portopen:
            print(f'{ip_address}:{port}: OPEN')
            print(f'TLS is available: {target_tlsopen}')
            # First check for redirects on whatever port we were told to scan
            # ...but only if we're connecting to port 80 or 443
            # if port == 80 or port == 443:
            #     # Now we also pass in whether TLS is available so we know whether to try TLS regardless of the port
            #     redirection_results = redirect_hostname(hostname, port, target_tlsopen)

            http_body = input_data['http_body']  # boolean variable for HTTP pages info
            redirection_results, http_data = get_http(ip_address, host_sni, port, target_tlsopen, http_body, force_redirect)

            if redirection_results == 'ERROR: Connection failed':
                str_host = hostname  # default to original hostname if redirects failed
                str_path = '/'  # default path
                b_httptohttps = False
            else:
                str_host = redirection_results[0]  # updated hostname
                str_path = redirection_results[1]  # updated path
                b_httptohttps = redirection_results[2]  # updated http to https redirect

            if 'TLS' in input_data['scans']:
                if target_tlsopen:
                    # List to hold desired ScanCommands for later
                    commands_to_run = []
                    # Read in command list
                    for param in input_data['tls_params']:  # this currently assumes that params are only given for tls
                        if param in tls_command_list:
                            commands_to_run.append(str(param))
                    tls_data = tls_scan(ip_address, str_host, commands_to_run, port)
                else:
                    print("Port closed - no TLS data available")
                    tls_data = "Port closed - no TLS data available"

            if 'HTTP2' in input_data['scans']:
                http2_data = check_http2(host_path, port)

            metadata.update({'http_to_https': b_httptohttps})
            metadata.update({'status': "Successful"})
        else:
            metadata.update({'status': "Failed"})
            print(f"{hostname}:{port} is closed")

        end_time = datetime.today()
        metadata.update({'start': start_time.__str__()})
        metadata.update({'end': end_time.__str__()})
        scan_data.update({'scan_metadata': metadata})  # add metadata to beginning of dictionary

        # Add results of scans (boolean defaults to false if dictionary is empty)
        if 'HTTP' in input_data['scans']:
            scan_data.update({'http_headers': http_data})
        if tls_data:
            scan_data.update({'tls_scan': tls_data})
        if 'DNS' in input_data['scans']:
            scan_data.update({'dns': dns_data})
        if http2_data:
            scan_data.update({'http2': http2_data})

        if input_data['print_out']:
            print_to_console(str_host, tls_data, http_data, http2_data, dns_data, b_httptohttps, force_redirect)

        print('\nScans complete')
        print('-------------------------------------')
        print(f'Total run time: {end_time - start_time}')

    return scan_data, hostname


if __name__ == "__main__":
    scanner_driver()
