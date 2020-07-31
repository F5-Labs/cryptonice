# cryptonice
# gettls.py

from sslyze import (
    ServerNetworkLocationViaDirectConnection,
    ServerConnectivityTester,
    Scanner,
    ServerScanRequest,
    ScanCommand
)
from sslyze.errors import ConnectionToServerFailed

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed448, ed25519
from datetime import datetime
from typing import List, cast


warning_bad_ciphers = {"_RC4_": ["HIGH - RC4", "The RC4 symmetric cipher is considered weak and should not be used"],
                        "_MD5": ["HIGH - MD5", "The MD5 message authentication code is considered weak and should not be used"],
                        "_3DES_": ["HIGH - 3DES", "The 3DES symmetric cipher is vulnerable to the Sweet32 attack"]}


def createServerConnections(ip_address, hostname, servers_to_scan, port_to_scan):
    """
    Create connections to each server in ip_list, store connection results in servers_to_scan list
    :param ip_address: IP address to connect to
    :param hostname: name of host to connect to
    :param servers_to_scan: list of open server connections
    :param port_to_scan: desired port to attempt connection with
    :return: None
    """
    server_location = ServerNetworkLocationViaDirectConnection(str(hostname), port_to_scan, ip_address)
    try:
        server_info = ServerConnectivityTester().perform(server_location)
        servers_to_scan.append(server_info)
        return "success"
    except ConnectionToServerFailed as e:
        return f"Error connecting to {server_location.hostname}:{server_location.port}: {e.error_message}"


def addScanRequests(scanner, servers_to_scan, commands):
    """
    Queue scan requests for each open server connections
    :param scanner: Scanner object which holds connections open for each IP
    :param servers_to_scan: list of open connections
    :param commands: set of string scan commands (like 'certificate_info' and 'tls_1_0_cipher_suites'
    :return: None
    """
    print('Queueing TLS scans (this might take a little while...)')
    for server_info in servers_to_scan:
        server_scan_req = ServerScanRequest(
            server_info=server_info, scan_commands=commands
        )
        scanner.queue_scan(server_scan_req)


def getCertificateResults(certificate):
    """
    Get certificate data and store in dictionary
    :param certificate: string literal certificate in PEM format
    :return: dictionary containing key-value pairs for all certificate information
    """
    cert_data = {}
    recommendations_data = {}
    # utf8 is more compatible with python3 so running an earlier version might cause an issue here...
    # cert is an object of the x509 Certificate class with attributes that can be found
    # here: https://cryptography.io/en/latest/x509/reference/#x-509-certificate-object
    cert = x509.load_pem_x509_certificate(certificate.encode('utf8'), default_backend())

    try:
        common_name = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        issuer_name = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        cert_data.update({'common_name': common_name, 'issuer_name': issuer_name})
    except:
        pass

    # Certificate serial number
    serial_num = cert.serial_number.__str__()
    cert_data.update({'serial_number': serial_num})

    # Certificate public key
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        cert_data.update({'public_key_algorithm': "RSA"})
    elif isinstance(public_key, dsa.DSAPublicKey):
        cert_data.update({'public_key_algorithm': "DSA"})
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        cert_data.update({'public_key_algorithm': "EllipticCurve"})
        cert_data.update({'curve_algorithm': public_key.curve.name})
    elif isinstance(public_key, ed25519.Ed25519PublicKey):
        cert_data.update({'public_key_algorithm': "Ed25519"})
    elif isinstance(public_key, ed448.Ed448PublicKey):
        cert_data.update({'public_key_algorithm': "Ed448"})
    else:
        cert_data.update({'public_key_algorithm': "UNKNOWN"})
    # Certificate public key size (attribute of public key object)
    cert_data.update({'public_key_size': public_key.key_size})

    # Certificate validity dates
    not_valid_before = cert.not_valid_before.__str__()
    cert_data.update({'valid_from': not_valid_before})
    not_valid_after = cert.not_valid_after.__str__()
    cert_data.update({'valid_until': not_valid_after})

    cert_days_left = ((datetime.strptime(not_valid_after, '%Y-%m-%d %H:%M:%S')) - datetime.today()).days
    cert_data.update({'days_left': cert_days_left})

    if cert_days_left < 0:
        recommendations_data.update({'CRITICAL - Cert Expiry': 'Certificate has expired!'})
    elif cert_days_left < 1:
        recommendations_data.update({'HIGH - Cert Expiry': 'Certificate has less than 1 day remaining'})
    elif cert_days_left < 7:
        recommendations_data.update({'WARN - Cert Expiry': 'Certificate has less than 7 days remaining'})
    elif cert_days_left < 14:
        recommendations_data.update({'INFO - Cert Expiry': 'Certificate has less than 14 days remaining'})


    # Certificate SHA (signature_hash_algorithm returns a HashAlgorithm object with the attribute 'name')
    sha = cert.signature_hash_algorithm.name
    cert_data.update({'signature_algorithm': sha})

    try:
        """These lines of code are copied from sslyze/sslyze/plugins/certificate_info/_certificate_utils.py"""
        subj_alt_names = List[str]
        san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_ext_value = cast(x509.SubjectAlternativeName, san_ext.value)
        subj_alt_names = san_ext_value.get_values_for_type(x509.DNSName)
        cert_data.update({'subject_alt_names': subj_alt_names})
    except x509.ExtensionNotFound:
        cert_data.update({'subject_alt_names': []})

    connection_data.update({'cert_recommendations': recommendations_data})

    return cert_data


def tls_scan(ip_address, str_host, commands_to_run, port_to_scan):
    servers_to_scan = []
    start_date = datetime.today()

    global connection_data

    # Loop through all hostnames and attempt to connect
    # if error message is returned (ie scanner could not connect, return error message and exit function)
    error = createServerConnections(ip_address, str_host, servers_to_scan, port_to_scan)
    if error != 'success':
        connection_data = {}
        connection_data.update({'tls_error': error.__str__()})
        return connection_data  # exit function early

    scanner = Scanner()

    # Queue the desired scan commands for each server
    addScanRequests(scanner, servers_to_scan, commands_to_run)

    for server_scan_result in scanner.get_results():
        connection_data = {}  # Dictionary to hold data until it is written to JSON file
        recommendations_data = {}

        # Get IP address hostname
        hostname = server_scan_result.server_info.server_location.hostname

        # Collect relevant information from server_info results
        ip_address = server_scan_result.server_info.server_location.ip_address
        cipher_suite_supported = server_scan_result.server_info.tls_probing_result.cipher_suite_supported
        client_auth_requirement = \
            server_scan_result.server_info.tls_probing_result.client_auth_requirement.name
        highest_tls_v_supported = \
            server_scan_result.server_info.tls_probing_result.highest_tls_version_supported.name

        # Add information to dictionary
        connection_data.update({'hostname': hostname})  # from server location
        connection_data.update({'ip_address': ip_address})  # from server location
        connection_data.update({'cipher_suite_supported': cipher_suite_supported})  # from tls_probing_result
        connection_data.update({'client_authorization_requirement': client_auth_requirement})  # from tls_probing_result
        connection_data.update({'highest_tls_version_supported': highest_tls_v_supported})  # from tls_probing_result

        if 'certificate_info' in commands_to_run:
            try:
                certinfo_result = server_scan_result.scan_commands_results[ScanCommand.CERTIFICATE_INFO]
                all_certificates_info = {}
                # cycle through all certificates (IP may have more than one)
                count: int = 0
                for cert_deployment in certinfo_result.certificate_deployments:
                    if count == 0:
                        all_certificates_info.update({'leaf_certificate_has_must_staple_extension':
                                                          cert_deployment.leaf_certificate_has_must_staple_extension})
                        all_certificates_info.update({'leaf_certificate_is_ev': cert_deployment.leaf_certificate_is_ev})
                        all_certificates_info.update({'leaf_certificate_signed_certificate_timestamps_count':
                                                          cert_deployment.leaf_certificate_signed_certificate_timestamps_count})
                        all_certificates_info.update({'leaf_certificate_subject_matches_hostname': cert_deployment.
                                                     leaf_certificate_subject_matches_hostname})
                        ocsp_response = cert_deployment.ocsp_response
                        if ocsp_response is not None:
                            ocsp_response_data = {}
                            if ocsp_response.status.value == 0:
                                ocsp_response_data.update({'status': 'SUCCESSFUL'})
                                ocsp_response_data.update({'type': ocsp_response.type})
                                ocsp_response_data.update({'version': ocsp_response.version})
                                ocsp_response_data.update({'responder_id': ocsp_response.responder_id})
                                ocsp_response_data.update({'certificate_status': ocsp_response.certificate_status})
                                ocsp_response_data.update({'hash_algorithm': ocsp_response.hash_algorithm})
                                ocsp_response_data.update({'issuer_name_hash': ocsp_response.issuer_name_hash})
                                ocsp_response_data.update({'issuer_key_hash': ocsp_response.issuer_key_hash})
                                ocsp_response_data.update({'serial_number': ocsp_response.serial_number})
                            elif ocsp_response.status.value == 1:
                                ocsp_response_data.update({'status': 'MALFORMED_REQUEST'})
                            elif ocsp_response.status.value == 2:
                                ocsp_response_data.update({'status': 'INTERNAL_ERROR'})
                            elif ocsp_response.status.value == 3:
                                ocsp_response_data.update({'status': 'TRY_LATER'})
                            elif ocsp_response.status.value == 5:
                                ocsp_response_data.update({'status': 'SIG_REQUIRED'})
                            elif ocsp_response.status.value == 6:
                                ocsp_response_data.update({'status': 'UNAUTHORIZED'})
                            all_certificates_info.update({'ocsp_response': ocsp_response_data})
                        else:
                            all_certificates_info.update({'ocsp_response': ocsp_response})
                        all_certificates_info.update(
                            {'ocsp_response_is_trusted': cert_deployment.ocsp_response_is_trusted})

                    # Create a dictionary with the path validation results for each validated trust store
                    trust_store_checks = {}
                    for path_validation_result in cert_deployment.path_validation_results:
                        if path_validation_result.was_validation_successful:
                            trust_store_checks.update(
                                {path_validation_result.trust_store.name: path_validation_result.openssl_error_string})

                    # Code from sslyze for reference (we can use the was_validation_successful variable if needed)
                    # for path_validation_result in all_path_validation_results:
                    #     if path_validation_result.was_validation_successful:
                    #         trust_store_that_can_build_verified_chain = path_validation_result.trust_store
                    #         verified_certificate_chain = path_validation_result.verified_certificate_chain
                    #         break

                    # Check for certificate errors (using Mozilla as the trust store to check against)
                    certificate_errors = {}
                    if "Mozilla" in trust_store_checks.keys() and trust_store_checks.get("Mozilla") is None:
                        certificate_errors.update({'cert_trusted': True})
                    elif "Mozilla" in trust_store_checks.keys():
                        certificate_errors.update({'cert_trusted': False})
                        certificate_errors.update({'cert_error': trust_store_checks.get("Mozilla")})
                    else:
                        certificate_errors.update({'cert_trusted': False})
                        certificate_errors.update({'cert_error': "Mozilla not trusted"})
                    certificate_errors.update({'hostname_matches': cert_deployment.leaf_certificate_subject_matches_hostname})

                    # Collect certificate (returns a string literal from CertificateDeploymentAnalysisResult class)
                    certificate = cert_deployment.received_certificate_chain_as_pem[count]

                    # Returns updated dictionary with certificate information
                    certificate_info = getCertificateResults(certificate)
                    # Add possible certificate errors to dictionary
                    certificate_info.update({'certificate_errors': certificate_errors})

                    # Add certificate data to overall scan dictionary
                    all_certificates_info.update({'certificate_' + str(count): certificate_info})
                    count += 1
                connection_data.update({"certificate_info": all_certificates_info})
            except KeyError:
                pass

        if 'ssl_2_0_cipher_suites' in commands_to_run:  # Collect results for accepted SSL 2.0 cipher suites
            try:
                ssl2_data = {}
                ssl2_result = server_scan_result.scan_commands_results[ScanCommand.SSL_2_0_CIPHER_SUITES]

                preferred_cipher_suite = ssl2_result.cipher_suite_preferred_by_server
                if preferred_cipher_suite is not None:
                    ssl2_data.update({'preferred_cipher_suite': preferred_cipher_suite.cipher_suite.name})
                else:
                    ssl2_data.update({'preferred_cipher_suite': None})

                cipher_suite_list = []
                for accepted_cipher_suite in ssl2_result.accepted_cipher_suites:
                    cipher_suite_list.append(accepted_cipher_suite.cipher_suite.name)
                    recommendations_data.update({'CRITICAL - SSLv2': 'SSLv2 is severely broken and should be disabled. Recommend disabling SSLv2 immediately. '})
                ssl2_data.update({'accepted_ssl_2_0_cipher_suites': cipher_suite_list})
                connection_data.update({'ssl_2_0': ssl2_data})
            except KeyError:
                pass

        if 'ssl_3_0_cipher_suites' in commands_to_run:  # Collect results for accepted SSL 3.0 cipher suites
            try:
                ssl3_data = {}
                ssl3_result = server_scan_result.scan_commands_results[ScanCommand.SSL_3_0_CIPHER_SUITES]

                preferred_cipher_suite = ssl3_result.cipher_suite_preferred_by_server
                if preferred_cipher_suite is not None:
                    ssl3_data.update({'preferred_cipher_suite': preferred_cipher_suite.cipher_suite.name})
                else:
                    ssl3_data.update({'preferred_cipher_suite': None})

                cipher_suite_list = []
                for accepted_cipher_suite in ssl3_result.accepted_cipher_suites:
                    cipher_suite_list.append(accepted_cipher_suite.cipher_suite.name)
                    recommendations_data.update({'CRITICAL - SSLv3': 'You may be vulnerable to the POODLE attack. Recommend disabling SSLv3 immediately. '})
                ssl3_data.update({'accepted_ssl_3_0_cipher_suites': cipher_suite_list})
                connection_data.update({'ssl_3_0': ssl3_data})
            except KeyError:
                pass

        if 'tls_1_0_cipher_suites' in commands_to_run:  # Collect results for accepted TLS 1.0 cipher suites
            try:
                tls1_0_data = {}
                tls1_0_result = server_scan_result.scan_commands_results[ScanCommand.TLS_1_0_CIPHER_SUITES]

                preferred_cipher_suite = tls1_0_result.cipher_suite_preferred_by_server
                if preferred_cipher_suite is not None:
                    tls1_0_data.update({'preferred_cipher_suite': preferred_cipher_suite.cipher_suite.name})
                else:
                    tls1_0_data.update({'preferred_cipher_suite': None})

                cipher_suite_list = []
                cipher_suite_warning = []
                for accepted_cipher_suite in tls1_0_result.accepted_cipher_suites:
                    cipher_suite_list.append(accepted_cipher_suite.cipher_suite.name)
                    recommendations_data.update({'HIGH - TLSv1.0': 'Major browsers are disabling TLS 1.0 imminently. Carefully monitor if clients still use this protocol. '})

                    # See if this cipher suite is in the dictionary of weak ciphers
                    for key, dict_warning in warning_bad_ciphers.items():
                        # Check if a bad cipher is in the list of ciphers support, but ignore if we've already come across it
                        if (key in accepted_cipher_suite.cipher_suite.name) and not (key in cipher_suite_warning):
                            cipher_suite_warning.append(key)
                            recommendations_data.update({dict_warning[0]: dict_warning[1]})

                tls1_0_data.update({'accepted_tls_1_0_cipher_suites': cipher_suite_list})
                connection_data.update({'tls_1_0': tls1_0_data})
            except KeyError:
                pass

        if 'tls_1_1_cipher_suites' in commands_to_run:  # Collect results for accepted TLS 1.1 cipher suites
            try:
                tls1_1_data = {}
                tls1_1_result = server_scan_result.scan_commands_results[ScanCommand.TLS_1_1_CIPHER_SUITES]

                preferred_cipher_suite = tls1_1_result.cipher_suite_preferred_by_server
                if preferred_cipher_suite is not None:
                    tls1_1_data.update({'preferred_cipher_suite': preferred_cipher_suite.cipher_suite.name})
                else:
                    tls1_1_data.update({'preferred_cipher_suite': None})

                cipher_suite_list = []
                for accepted_cipher_suite in tls1_1_result.accepted_cipher_suites:
                    cipher_suite_list.append(accepted_cipher_suite.cipher_suite.name)
                    recommendations_data.update({'HIGH - TLSv1.1': 'Major browsers are disabling this TLS 1.1 immenently. Carefully monitor if clients still use this protocol. '})

                    # See if this cipher suite is in the dictionary of weak ciphers
                    for key, dict_warning in warning_bad_ciphers.items():
                        # Check if a bad cipher is in the list of ciphers support, but ignore if we've already come across it
                        if (key in accepted_cipher_suite.cipher_suite.name) and not (key in cipher_suite_warning):
                            cipher_suite_warning.append(key)
                            recommendations_data.update({dict_warning[0]: dict_warning[1]})

                tls1_1_data.update({'accepted_tls_1_1_cipher_suites': cipher_suite_list})
                connection_data.update({'tls_1_1': tls1_1_data})
            except KeyError:
                pass

        if 'tls_1_2_cipher_suites' in commands_to_run:  # Collect results for accepted TLS 1.2 cipher suites
            try:
                tls1_2_data = {}
                tls1_2_result = server_scan_result.scan_commands_results[ScanCommand.TLS_1_2_CIPHER_SUITES]

                preferred_cipher_suite = tls1_2_result.cipher_suite_preferred_by_server
                if preferred_cipher_suite is not None:
                    tls1_2_data.update({'preferred_cipher_suite': preferred_cipher_suite.cipher_suite.name})
                else:
                    tls1_2_data.update({'preferred_cipher_suite': None})

                cipher_suite_list = []
                for accepted_cipher_suite in tls1_2_result.accepted_cipher_suites:
                    cipher_suite_list.append(accepted_cipher_suite.cipher_suite.name)
                tls1_2_data.update({'accepted_tls_1_2_cipher_suites': cipher_suite_list})
                connection_data.update({'tls_1_2': tls1_2_data})
            except KeyError:
                pass

        if 'tls_1_3_cipher_suites' in commands_to_run:  # Collect results for accepted TLS 1.3 cipher suites
            try:
                tls1_3_data = {}
                tls1_3_result = server_scan_result.scan_commands_results[ScanCommand.TLS_1_3_CIPHER_SUITES]

                preferred_cipher_suite = tls1_3_result.cipher_suite_preferred_by_server
                if preferred_cipher_suite is not None:
                    tls1_3_data.update({'preferred_cipher_suite': preferred_cipher_suite.cipher_suite.name})
                else:
                    tls1_3_data.update({'preferred_cipher_suite': None})

                cipher_suite_list = []
                for accepted_cipher_suite in tls1_3_result.accepted_cipher_suites:
                    cipher_suite_list.append(accepted_cipher_suite.cipher_suite.name)
                tls1_3_data.update({'accepted_tls_1_3_cipher_suites': cipher_suite_list})
                connection_data.update({'tls_1_3': tls1_3_data})
            except KeyError:
                pass

        test_results = {}  # dictionary to store results of optional tests

        if 'tls_compression' in commands_to_run:  # Collect results for TLS compression test
            try:
                tls_compression_result = server_scan_result.scan_commands_results[ScanCommand.TLS_COMPRESSION]
                if tls_compression_result.supports_compression:
                    test_results.update({'compression_supported': True})
                else:
                    test_results.update({'compression_supported': False})
            except KeyError:
                pass

        if 'tls_1_3_early_data' in commands_to_run:  # Collect results for early data acceptance
            try:
                tls1_3_early_result = server_scan_result.scan_commands_results[ScanCommand.TLS_1_3_EARLY_DATA]
                if tls1_3_early_result.supports_early_data:
                    test_results.update({'accepts_early_data': True})
                else:
                    test_results.update({'accepts_early_data': False})
            except KeyError:
                pass

        if 'openssl_ccs_injection' in commands_to_run:  # Collect results for CVE-2014-0224 vulnerability
            try:
                openssl_css_injection_result = server_scan_result.scan_commands_results[
                    ScanCommand.OPENSSL_CCS_INJECTION]
                if openssl_css_injection_result.is_vulnerable_to_ccs_injection:
                    test_results.update({'CVE-2014-0224_vulnerable': True})
                else:
                    test_results.update({'CVE-2014-0224_vulnerable': False})
            except KeyError:
                pass

        if 'tls_fallback_scsv' in commands_to_run:  # Collect results for TLS fallback result
            try:
                tls_fallback_result = server_scan_result.scan_commands_results[ScanCommand.TLS_FALLBACK_SCSV]
                if tls_fallback_result.supports_fallback_scsv:
                    test_results.update({'supports_tls_fallback': True})
                else:
                    test_results.update({'supports_tls_fallback': False})
            except KeyError:
                pass

        if 'heartbleed' in commands_to_run:  # Collect results for heartbleed vulnerability
            try:
                heartbleed_result = server_scan_result.scan_commands_results[ScanCommand.HEARTBLEED]
                if heartbleed_result.is_vulnerable_to_heartbleed:
                    test_results.update({'vulnerable_to_heartbleed': True})
                else:
                    test_results.update({'vulnerable_to_heartbleed': False})
            except KeyError:
                pass

        if 'robot' in commands_to_run:  # Collect results for robot vulnerability
            try:
                obj_robot_result = server_scan_result.scan_commands_results[ScanCommand.ROBOT]
                int_robot_results = obj_robot_result.robot_result.value
                # server_info.tls_probing_result.highest_tls_version_supported.name
                if int_robot_results == 1:
                    test_results.update({'vulnerable_to_robot': [True, 'Weak oracle']})
                    recommendations_data.update({'CRITICAL - ROBOT': 'ROBOT vulnerability detected. Recommend disabling RSA encryption and using DH, ECDH, DHE or ECDHE.'})
                elif int_robot_results == 2:
                    test_results.update({'vulnerable_to_robot': [True, 'Strong oracle']})
                    recommendations_data.update({'CRITICAL - ROBOT': 'ROBOT vulnerability detected. Recommend disabling RSA encryption and using DH, ECDH, DHE or ECDHE.'})
                elif int_robot_results == 3:
                    test_results.update({'vulnerable_to_robot': [False, 'No oracle']})
                elif int_robot_results == 4:
                    test_results.update({'vulnerable_to_robot': [False, 'No RSA']})
                elif int_robot_results == 5:
                    test_results.update({'vulnerable_to_robot': [False, '']})
                else:
                    test_results.update({'vulnerable_to_robot': [False, 'Test failed']})
            except KeyError:
                pass

        # Section not finished yet, will come back to it
        if 'http_headers' in commands_to_run:
            http_info = {}
            try:
                http_results = server_scan_result.scan_commands_results[ScanCommand.HTTP_HEADERS]
                strict_transport_security_header = http_results.strict_transport_security_header
                if strict_transport_security_header is not None:
                    strict_transport_info = {}
                    strict_transport_info.update({'preload': strict_transport_security_header.preload})
                    strict_transport_info.update(
                        {'include_subdomains': strict_transport_security_header.include_subdomains})
                    strict_transport_info.update({'max_age': strict_transport_security_header.max_age})
                    http_info.update({'strict_transport_security_header': strict_transport_info})
                public_key_pins_header = http_results.public_key_pins_header
                if public_key_pins_header is not None:
                    public_pins_info = {}
                    public_pins_info.update({'include_subdomains': public_key_pins_header.include_subdomains})
                    public_pins_info.update({'max_age': public_key_pins_header.max_age})
                    public_pins_info.update({'sha256_pins': public_key_pins_header.sha256_pins})
                    public_pins_info.update({'report_uri': public_key_pins_header.report_uri})
                    public_pins_info.update({'report_to': public_key_pins_header.report_to})
                    http_info.update({'public_key_pins_header': public_pins_info})
                public_key_pins_report_only_header = http_results.public_key_pins_report_only_header
                if public_key_pins_report_only_header is not None:
                    public_pins_report_info = {}
                    public_pins_report_info.update(
                        {'include_subdomains': public_key_pins_report_only_header.include_subdomains})
                    public_pins_report_info.update({'max_age': public_key_pins_report_only_header.max_age})
                    public_pins_report_info.update({'sha256_pins': public_key_pins_report_only_header.sha256_pins})
                    public_pins_report_info.update({'report_uri': public_key_pins_report_only_header.report_uri})
                    public_pins_report_info.update({'report_to': public_key_pins_report_only_header.report_to})
                    http_info.update({'public_key_pins_header': public_pins_report_info})
                expect_ct_headers = http_results.expect_ct_header
                if expect_ct_headers is not None:
                    expect_ct_info = {}
                    expect_ct_info.update({'max_age': expect_ct_headers.max_age})
                    expect_ct_info.update({'report_uri': expect_ct_headers.report_uri})
                    expect_ct_info.update({'enforce': expect_ct_headers.enforce})
                    http_info.update({'expect_ct_info': expect_ct_info})
                test_results.update({'http_headers': http_info})
            except KeyError:
                pass

        if 'session_renegotiation' in commands_to_run:
            try:
                renegotiation_results = server_scan_result.scan_commands_results[ScanCommand.SESSION_RENEGOTIATION]
                session_reneg = {}
                session_reneg.update(
                    {'accepts_client_renegotiation': renegotiation_results.accepts_client_renegotiation})
                session_reneg.update(
                    {'supports_secure_renegotiation': renegotiation_results.supports_secure_renegotiation})
                test_results.update({'session_renegotiation': session_reneg})
            except KeyError:
                pass

        if 'session_resumption' in commands_to_run:
            try:
                session_resumption_results = server_scan_result.scan_commands_results[ScanCommand.SESSION_RESUMPTION]
                if session_resumption_results.is_session_id_resumption_supported:
                    session_resumption_info = {}
                    session_resumption_info.update({'attempted_session_id_resumptions_count':
                                                        session_resumption_results.attempted_session_id_resumptions_count})
                    session_resumption_info.update({'successful_session_id_resumptions_count':
                                                        session_resumption_results.successful_session_id_resumptions_count})
                    if session_resumption_results.is_tls_ticket_resumption_supported:
                        if session_resumption_results.tls_ticket_resumption_result.value == 1:
                            session_resumption_info.update({'tls_ticket_resumption_results': 'SUCCEEDED'})
                        elif session_resumption_results.tls_ticket_resumption_result.value == 2:
                            session_resumption_info.update(
                                {'tls_ticket_resumption_results': 'FAILED_TICKET_NOT_ASSIGNED'})
                        elif session_resumption_results.tls_ticket_resumption_result.value == 3:
                            session_resumption_info.update({'tls_ticket_resumption_results': 'FAILED_TICKET_IGNORED'})
                        elif session_resumption_results.tls_ticket_resumption_result.value == 4:
                            session_resumption_info.update(
                                {'tls_ticket_resumption_results': 'FAILED_ONLY_TLS_1_3_SUPPORTED'})
                    test_results.update({'session_resumption': session_resumption_info})
            except KeyError:
                pass

        if 'session_resumption_rate' in commands_to_run:
            try:
                session_resumption_rate_results = server_scan_result.scan_commands_results[
                    ScanCommand.SESSION_RESUMPTION_RATE]
                session_resume_info = {}
                session_resume_info.update({'attempted_session_id_resumptions_count':
                                                session_resumption_rate_results.attempted_session_id_resumptions_count})
                session_resume_info.update({'successful_session_id_resumptions_count':
                                                session_resumption_rate_results.successful_session_id_resumptions_count})
                test_results.update({'session_resumption_rate': session_resume_info})
            except KeyError:
                pass

        # Add results of vulnerability testing to dictionary
        connection_data.update({'tests': test_results})

        # Scan meta data
        end_date = datetime.today()
        metadata = {}  # Metadata for scan
        metadata.update({'tls_scan_start': start_date.__str__()})
        metadata.update({'tls_scan_end': end_date.__str__()})
        metadata.update({'scan_parameters': commands_to_run})

        # Scan commands that were run with errors
        commands_with_errors = {}
        for scan_command, error in server_scan_result.scan_commands_errors.items():
            commands_with_errors.update({scan_command: error.exception_trace})
        metadata.update({'commands_with_errors': commands_with_errors})
        # Add meta data to overall information dictionary
        connection_data.update({'scan_information': metadata})

        # Add recommendations data to overall information dictionary
        connection_data.update({'tls_recommendations': recommendations_data})

        return connection_data


if __name__ == "__main__":
    tls_scan()