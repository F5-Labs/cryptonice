import json

def writeToJSONFile(filename, pathToJson, data):
    """
    Write contents of dictionary with hostname: certificate key-value pairs to a json file
    :param filename: name of destination filegit ad
    :param data: dictionary with key value pairs
    :return: None
    """
    if "/" in filename:
        filename = filename.split("/", 1)[0]

    if pathToJson[-1] != "/":
        pathToJson = pathToJson + "/"

    filePathNameWExt = pathToJson + filename + '.json'
    with open(filePathNameWExt, 'w') as fp:
        json.dump(data, fp, default=print_errors)
    print(f'\nOutputting data to {filePathNameWExt}')


def print_errors(error):
    try:
        return {"ERROR": error.__str__()}
    except:
        return {"ERROR": "Not JSON serializable"}


def print_to_console(str_host, scan_data, b_httptohttps, force_redirect):
    print('\n')
    print('RESULTS')
    print('-------------------------------------')
    print(f'Hostname:\t\t\t  {str_host}\n')

    tls_data = scan_data.get('tls')
    http2_data = scan_data.get('http2')
    http_data = scan_data.get('http')
    dns_data = scan_data.get('dns')
    jarm_data = scan_data.get('jarm')

    if tls_data == "Port closed - no TLS data available":
        print('***TLS Results***')
        print(f'Port closed - no TLS data available')
    elif tls_data == "No TLS scan parameters provided":
        print('***TLS Results***')
        print('No TLS scan parameters provided')
    elif tls_data:
        print(f'Selected Cipher Suite:\t\t  {tls_data.get("cipher_suite_supported")}')
        print(f'Selected TLS Version:\t\t  {tls_data.get("highest_tls_version_supported")}')

        print('\nSupported protocols:')
        # TLS 1.3 results
        try:
            tls_1_3_support = True if tls_data.get("tls_1_3").get("accepted_tls_1_3_cipher_suites") != [] else False
            early_data = tls_data.get("tests").get("accepts_early_data")
            if tls_1_3_support:
                print(f'TLS 1.3:\t\t\t  Yes {"(early data supported)" if early_data else ""}')
        except:
            pass

        # TLS 1.2 results
        try:
            if tls_data.get("tls_1_2").get("accepted_tls_1_2_cipher_suites"):
                print('TLS 1.2:\t\t\t  Yes')
        except:
            pass

        # TLS 1.1 results
        try:
            if tls_data.get("tls_1_1").get("accepted_tls_1_1_cipher_suites"):
                print('TLS 1.1:\t\t\t  Yes')
        except:
            pass

        # TLS 1.0 results
        try:
            if tls_data.get("tls_1_0").get("accepted_tls_1_0_cipher_suites"):
                print('TLS 1.0:\t\t\t  Yes')
        except:
            pass

        # SSL 3.0 results
        try:
            if tls_data.get("ssl_3_0").get("accepted_ssl_3_0_cipher_suites"):
                print('SSL 3.0:\t\t\t  Yes')
        except:
            pass

        try:
            if tls_data.get("ssl_2_0").get("accepted_ssl_2_0_cipher_suites"):
                print('SSL 2.0:\t\t\t  Supported')

        except:
            pass


        # JARM TLS fingerprint results
        if isinstance(jarm_data, str):
            print(jarm_data)
        elif jarm_data:
            print(f'\nTLS fingerprint:\t\t  {jarm_data.get("fingerprint")}')
        print('')


        # HTTP/2 results
        if isinstance(http2_data, str):
            print(http2_data)
        elif http2_data:
            print(f'\nHTTP/2 supported:\t\t  {http2_data.get("http2")}')
        print('')

    # Print certificate data if it was collected
    try:
        cert_0 = tls_data.get("certificate_info").get("certificate_0")
        try:
            # Unless this is a self-signed cert, there should be at least 1 more cert in the chain
            cert_1 = tls_data.get("certificate_info").get("certificate_1")
        except:
            pass

        print(f'\nCERTIFICATE')
        print(f'Common Name:\t\t\t  {cert_0.get("common_name")}')
        print(f'Issuer Name:\t\t\t  {cert_0.get("issuer_name")}')
        print(f'Public Key Algorithm:\t\t  {cert_0.get("public_key_algorithm")}')
        print(f'Public Key Size:\t\t  {cert_0.get("public_key_size")}')
        if cert_0.get("public_key_algorithm") == "EllipticCurvePublicKey":
            print(f'Curve Algorithm:\t\t  {cert_0.get("curve_algorithm")}')
        print(f'Signature Algorithm:\t\t  {cert_0.get("signature_algorithm")}')
        print('')

        try:
            # Grab the common name from cert_1 (which is the issuer of cert_0)
            # For some sites, however, only a single cert is returned to the dictionary object
            print(f'Certificate signed by:\t\t  {cert_1.get("common_name")}')
        except:
            pass

        cert_errors = cert_0.get("certificate_errors")
        cert_error = ""
        try:
            cert_error = cert_errors.get("cert_error")
            if cert_error is None:
                cert_error = "No errors"
        except KeyError:
            pass

        print(f'Certificate is trusted:\t\t  {cert_errors.get("cert_trusted")} ({cert_error})')
        print(f'Hostname Validation:\t\t  {"OK - Certificate matches server hostname" if cert_errors.get("hostname_matches") else "FAILED - Certificate does NOT match server hostname"}')
        print(f'Extended Validation:\t\t  {True if tls_data.get("certificate_info").get("leaf_certificate_is_ev") else False}')
        print(f'Certificate is in date:\t\t  {True if cert_0.get("valid_from") < datetime.today().__str__() < cert_0.get("valid_until") else False}')

        print(f'Days until expiry:\t\t  {cert_0.get("days_left")}')
        print(f'Valid From:\t\t\t  {cert_0.get("valid_from")}')
        print(f'Valid Until:\t\t\t  {cert_0.get("valid_until")}')
        print('')

        try:
            print(
                f'OCSP Response:\t\t\t  {"Successful" if tls_data.get("certificate_info").get("ocsp_response") is not None else "Unsuccessful"}')
            print(
                f'Must Staple Extension:\t\t  {True if tls_data.get("certificate_info").get("leaf_certificate_has_must_stable_extension") else False}')
        except:
            pass
        print('')

        print(f'Subject Alternative Names:')
        for name in cert_0.get("subject_alt_names"):
            print(f'\t  {name}')

        # Results from vulnerability tests (note: early data test captured in TLS 1.3 section)

        try:
            vuln_tests = tls_data.get('tests')
            other_test_run = False
            print('\nVulnerability Tests:')
            if vuln_tests.get("compression_supported") is not None:
                other_test_run = True
                print(f'Supports TLS Compression:\t  {vuln_tests.get("compression_supported")}')
            if vuln_tests.get("supports_tls_fallback") is not None:
                other_test_run = True
                print(f'Supports TLS Fallback:\t\t  {vuln_tests.get("supports_tls_fallback")}')
            if vuln_tests.get("CVE-2014-0224_vulnerable") is not None:
                other_test_run = True
                print(f'Vulnerable to CVE-2014-0224:\t  {vuln_tests.get("CVE-2014-0224_vulnerable")}')
            if vuln_tests.get("vulnerable_to_heartbleed") is not None:
                other_test_run = True
                print(f'Vulnerable to Heartbleed:\t  {vuln_tests.get("vulnerable_to_heartbleed")}')
            if vuln_tests.get('vulnerable_to_robot') is not None:
                other_test_run = True
                robot = vuln_tests.get('vulnerable_to_robot')
                print(f'Vulnerable to ROBOT:\t\t  {robot[0]} ({robot[1]})')

            if not other_test_run:
                print("No vulnerability tests were run")
        except:
            pass
    except:
        pass

    # Print HTTP Data
    if force_redirect:
        print(f'\nHTTP to HTTPS redirect:\t\t  {True if b_httptohttps else False}')

    if http_data != {}:
        try:
            strict_transport_security = http_data.get("Headers").get("Strict-Transport-Security")
            if strict_transport_security is not None:
                print(f'HTTP Strict Transport Security:\t  True ({strict_transport_security})')
            else:
                print(f'HTTP Strict Transport Security:\t  False')
        except:
            pass

        # try:
        #     public_key_pins = http_data.get("Headers").get("Public-Key-Pins")
        #     if public_key_pins is not None:
        #         print(f'HTTP Public Key Pinning:\t  True')
        #         for pin in public_key_pins:
        #             print(f'\t\t {pin}')
        #     else:
        #         print(f'HTTP Public Key Pinning:\t  False')
        #     print('')
        # except:
        #     pass

        # try:
        #     print(f'Secure Cookies:\t\t\t  {True if http_data.get("Cookies") != "" else False}\n')
        # except:
        #     pass


    try:
        if dns_data.get("records").get("CAA"):
            print('\nCAA Restrictions:')
            for record in dns_data.get("records").get("CAA"):
                print(f'\t {record}')
        else:
            print('None')
    except:
        pass


    # PRINT RECOMMENDATIONS
    print('')
    print('RECOMMENDATIONS')
    print('-------------------------------------')

    try:
        tls_recommendations = tls_data.get('tls_recommendations')
        for key, value in tls_recommendations.items():
            print (f'{key} {value}')
    except:
        pass

    try:
        cert_recommendations = tls_data.get('cert_recommendations')
        for key, value in cert_recommendations.items():
            print (f'{key} {value}')
    except:
        pass

    try:
        dns_recommendations = dns_data.get('dns_recommendations')
        for key, value in dns_recommendations.items():
            print(f'{key} {value}')
    except:
        pass
