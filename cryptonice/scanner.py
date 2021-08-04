# cryptonice
# scanner.py

import socket, ipaddress

try:
    from .getgeo import getlocation
except ImportError:
    pass


from .output import writeToJSONFile, print_to_console
from .gettls import tls_scan
from .gethttp import get_http
from .getdns import get_dns
from .gethttp2 import check_http2
from .jarm import check_jarm
from .checkport import port_open
from .pwnedkeys import check_key
from datetime import datetime

from cryptonice.__init__ import __version__

cryptonice_version=__version__

tls_command_list = ['certificate_info', 'ssl_2_0_cipher_suites', 'ssl_3_0_cipher_suites', 'tls_1_0_cipher_suites',
                    'tls_1_1_cipher_suites', 'tls_1_2_cipher_suites', 'tls_1_3_cipher_suites', 'tls_compression',
                    'tls_1_3_early_data', 'openssl_ccs_injection', 'heartbleed', 'robot', 'tls_fallback_scsv',
                    'session_renegotiation', 'session_resumption', 'session_resumption_rate', 'http_headers']

tls_defaults = ['certificate_info', 'ssl_2_0_cipher_suites', 'ssl_3_0_cipher_suites', 'tls_1_0_cipher_suites',
                    'tls_1_1_cipher_suites', 'tls_1_2_cipher_suites', 'tls_1_3_cipher_suites', 'tls_compression',
                    'tls_1_3_early_data', 'http_headers']


def scanner_driver(input_data):
    b_httptohttps = False
    cryptonice_version = input_data['cn_version']
    job_id = input_data['id']
    port = input_data['port']
    geolocation = False

    try:
        geolocation = input_data['geolocation']
    except:
        pass

    #For mass scanning:
    site_pos = 0
    try:
        site_pos = int(input_data['site_pos'])
    except:
        pass

    if port is None:
        port = 443  # default to 443 if none is supplied in input file

    try:
        targets_present = input_data['targets']
    except KeyError:
        print("ERROR: No target specified")
        return None, None
    try:
        scans_supplied = input_data['scans']
    except KeyError:
        print("ERROR: No scan commands supplied")
        return None, None

    tls_data = {}
    http_data = {}
    dns_data = {}
    http2_data = {}
    geo_data = {}

    for hostname in input_data['targets']:  # host names to scan
        pwned_data = False
        jarm_data = False

        print ('Pre-scan checks\n-------------------------------------')
        # Check to see if user has supplied an SNI. If so, this SNI will be used for all tests unless overriden by the
        # HTTP redirect checks
        try:
            host_sni = input_data['sni']
        except KeyError:
            host_sni = ""

        """
        Quick and dirty checks to strip out protocol and any remaining slashes.
        This should be replaced with comprehensive function.
        """
        hostname = hostname.replace("http://", "")
        hostname = hostname.replace("https://", "")
        hostname = hostname.replace("/", "")

        host_path = hostname  # all functions should use host_path for consistency
        if host_sni == "":
            host_sni = hostname
        ip_address = ""

        print(f'Scanning {hostname} on port {port}...')

        start_time = datetime.today()  # added to scan metadata later
        scan_data = {}  # final dictionary with metadata and scan results
        metadata = {}  # track metadata
        metadata.update({'cryptonice_version': cryptonice_version})
        metadata.update({'job_id': job_id})
        metadata.update({'hostname': hostname})
        metadata.update({'port': port})
        metadata.update({'node_name': socket.gethostname()})

        # For mass scanning only
        metadata.update({'site_pos': site_pos})

        #########################################################################################################
        # We can also check DNS regardless of open ports since it's an independent protocol
        # At this point there should be no WWW. prefix or path, but it's a good idea to check and scrub it anyway

        goodToGo = False

        # First check if our target is actually a valid IP address...
        # If it is, set the IP address to the 'hostname',
        # if not, perform a DNS lookup
        try:
            ipaddress.ip_address(hostname)
            # If we have a valid IP, skip the DNS lookup...
            ip_address = hostname
            goodToGo = True
            print(f'{hostname} is already a valid IP')
        except ValueError:
            # Determine if we are only using DNS to get an IP address, or whether we should query for all records
            if 'DNS' in str(input_data['scans']).upper():
                dns_data = get_dns(hostname, True)
            else:
                dns_data = get_dns(hostname, False)

            if dns_data:
                try:
                    ip_address = dns_data.get('records').get('A')[0]  # get first IP in list
                    goodToGo = True
                    print(f'{hostname} resolves to {ip_address}')
                except:
                    str_error = "Unable to resolve " + hostname + "(domain does not exist or may not have any A records)"
                    dns_data = ({'Error': str_error})
                    print(str_error)

        #########################################################################################################

        #Assume we want to follow redirects unless the input parameter says otherwise
        force_redirect = True

        #All subsequent scans are now dependant on the goodToGo variable which is based on having a valid IP or performing a successful DNS lookup
        if goodToGo:
            str_host = hostname  # will allow data to be outputted even if port is closed
            # Now we begin the proper scans based on the port we've been asked to connect to
            target_portopen, target_tlsopen = port_open(ip_address, port)

            try:
                force_redirect = input_data['force_redirect']
            except KeyError:
                force_redirect = True

            if target_portopen:
                print(f'{ip_address}:{port}: OPEN')
                print(f'TLS is available: {target_tlsopen}')
                # First check for redirects on whatever port we were told to scan
                # ...but only if we're connecting to port 80 or 443
                # if port == 80 or port == 443:
                #     # Now we also pass in whether TLS is available so we know whether to try TLS regardless of the port
                #     redirection_results = redirect_hostname(hostname, port, target_tlsopen)

                try:
                    http_body = input_data['http_body']  # boolean variable for HTTP pages info
                except KeyError:
                    http_body = False

                redirection_results, http_data = get_http(ip_address, host_sni, port, target_tlsopen, http_body, force_redirect)

                if redirection_results == 'ERROR: Connection failed':
                    str_host = hostname  # default to original hostname if redirects failed
                    str_path = '/'  # default path
                    b_httptohttps = False
                else:
                    str_host = redirection_results[0]  # updated hostname
                    str_path = redirection_results[1]  # updated path
                    b_httptohttps = redirection_results[2]  # updated http to https redirect

                    # Update IP address based on new hostname in case it's changed
                    new_dns_data = get_dns(str_host, False)

                    if new_dns_data:
                        try:
                            ip_address = new_dns_data.get('records').get('A')[0]  # get first IP in list
                            goodToGo = True
                            print(f'{str_host} resolves to {ip_address}')
                        except:
                            str_error = "Unable to resolve " + str_host + "(domain does not exist or may not have any A records)"
                            new_dns_data = ({'Error': str_error})
                            print(str_error)

                    # Recheck redirection on hew host
                    redirection_results, http_data = get_http(ip_address, str_host, port, target_tlsopen, http_body, force_redirect)

                ############
                # Lookup geolocation using Maxmind database
                # NOTE: This is not enabled by default for public users of Cryptonice
                if geolocation:
                    try:
                        geo_data = getlocation(ip_address)
                    except:
                        print('You must have the Maxmind GeoIP 2 module installed to make use of geolocation lookups')
                ###########

                if 'TLS' in str(input_data['scans']).upper():
                    if target_tlsopen:
                        # List to hold desired ScanCommands for later
                        commands_to_run = []
                        # Read in command list
                        try:
                            tls_params = input_data['tls_params']
                            # If the TLS parameters are blank but the TLS scan option is present, then assume a default set of scans to run
                            if len(tls_params) == 0:
                                commands_to_run = tls_defaults
                            else:
                                for param in tls_params:
                                    # If the tls_params value in the JSON input file is 'all' then apply every TLS scan function automatically
                                    if (param.upper() == "ALL"):
                                        commands_to_run = tls_command_list
                                    else:
                                        if param in tls_command_list:
                                            commands_to_run.append(str(param))

                            tls_data = tls_scan(ip_address, str_host, commands_to_run, port)

                        except KeyError:
                            tls_data = "No TLS scan parameters provided"
                    else:
                        tls_data = {'ERROR': 'Could not perform TLS handshake'}

                try:
                    # Failing to get a certificate_0 result, for whatever reason, will cause this to fail so we need to be prepared to skip
                    if 'PWNED' in str(input_data['scans']).upper():
                        cert_fingerprint = tls_data['certificate_info']['certificate_0']['fingerprint']
                        pwned_data = check_key(cert_fingerprint)
                except:
                    pwned_data = {'Error': 'Failed to retrieve leaf certificate. Unable to obtain fingerprint to check for pwned key.'}

                if 'HTTP2' in str(input_data['scans']).upper():
                    http2_data = check_http2(host_path, port)

                #if 'JARM' in input_data['scans'] or 'jarm' in input_data['scans']:
                jarm_data = check_jarm(host_path, port)

                metadata.update({'http_to_https': b_httptohttps})
                metadata.update({'status': "Successful"})
            else:
                metadata.update({'status': "Failed"})
                print(f"{hostname}:{port} is closed")

        #End of goodToGo IF block



        end_time = datetime.today()
        metadata.update({'start': start_time.__str__()})
        metadata.update({'end': end_time.__str__()})

        # add metadata to beginning of dictionary
        scan_data.update({'scan_metadata': metadata})

        # Add results of scans (boolean defaults to false if dictionary is empty)
        if 'HTTP' in input_data['scans'] or 'http' in input_data['scans']:
            scan_data.update({'http': http_data})
        if http2_data:
            scan_data.update({'http2': http2_data})
        if pwned_data:
            tls_data.update({'pwnedkeys': pwned_data})
        if jarm_data:
            tls_data.update({'jarm': jarm_data})
        if tls_data:
            scan_data.update({'tls': tls_data})
        if dns_data:
            scan_data.update({'dns': dns_data})
        if geolocation:
            scan_data.update({'geo': geo_data})


        if input_data['print_out']:
            print_to_console(hostname, scan_data, b_httptohttps, force_redirect)

        print('\nScans complete')
        print('-------------------------------------')
        print(f'Total run time: {end_time - start_time}')



        if input_data['generate_json']:
            try:
                pathToJson = input_data['json_path']
            except:
                pathToJson = "./"
            writeToJSONFile(hostname, pathToJson, scan_data)


    return scan_data, hostname


if __name__ == "__main__":
    scanner_driver()
