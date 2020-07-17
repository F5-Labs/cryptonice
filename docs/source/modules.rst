Modules
=======

scanner.py
^^^^^^^^^^

**def scanner_driver(input_data)** 

Scanner_driver is the main function of the library from which all other modules can be accessed. It will call functions to collect the requested data, based on the input provided in the input_data dictionary. As results are collected from each module, scanner_driver builds an output dictionary called scan_data with the information. This dictionary is then used to print output to the console, written to a JSON file, and returned to the function that called scanner driver (i.e. a function in another project or from a separate __main__ file).

  * *input_data*: dictionary formatted with all necessary scan information (see documentation for example) 

  * *return*: dictionary of scan data, hostname 

**def print_output_to_console(scan_data, b_httptohttps)**

Print_output_to_console is the function used to print the scan results to the console. This is a useful function to make the data more readable, especially because the JSON output (if created), is written on a single line. Print_output_to_console also generates recommendations to improve the TLS configuration of the target host.

  * *scan_data*: dictionary of all output from each module called from scanner_driver 

  * *b_httptohttps*: Boolean variable noting automatic redirect to HTTPS from HTTP (collected from gethttp.get_http)   

  * *return*: None 

**def writeToJSONFile(filename, data)** 

WriteToJSONFile receives a filename and a dictionary of scan data, and writes it to a single-line JSON file in the same directory as the scanner.py function. If any of the data is not immediately JSON serializable, WriteToJSONFile will call a helper function called print_errors that will attempt to return a string representation of the error. If this fails, it will return a message saying the particular input was not JSON serializable.

  * *filename*: string of hostname

  * *data*: dictionary of all scan data to convert to JSON 

  * *return*: None  

checkport.py
^^^^^^^^^^^^

**def port_open(hostname, port)**

Port_open is a quick way to check that the port the user would like to scan is open. If it isn’t open for connections, the program will terminate early. The function also checks to see if the hostname can also make a TLS connection.

  * *hostname*: string

  * *port*: int

  * *return*: Boolean open_port, open_tls (true if provided port is open, true if TLS is available aka port 443 is open)

modules/gettls.py
^^^^^^^^^^^^^^^^^

**def tls_scan(ip_address, str_host, commands_to_run, port_to_scan)**

Tls_scan is the main function of the TLS module. A server connection is created and scan commands are queued for the connection. The data from each of the scan commands is appended to a dictionary object which is returned at the end of the function. Certificate information is collected first, including various leaf certificate validity checks, and trust store information. Cryptonice currently only trusts Mozilla certificates, information that is recorded in the cert_errors portion of the tls_scan dictionary data. Cipher suite information is collected, if requested, and the accepted cipher suites for the selected SSL/TLS versions are listed. The vulnerability tests for TLS configuration are recorded largely as boolean variables (true if vulnerable, false if not), except for the ROBOT tests which provides a message related to why it is or isn’t vulnerable to ROBOT. After the tests are completed, the data is added to the larger tls_scan dictionary. Metadata is appended and it is returned to the function that called the tls_scan function.

  * *ip_address*: string host IP address to scan

  * *str_host*: string hostname (SNI)

  * *commands_to_run*: list of scan parameters

  * *port_to_scan*: int port to scan

  * *return*: dictionary of TLS data


**def createServerConnection(ip_address, str_host, servers_to_scan, port_to_scan)**

CreateServerConnection sets up a connection to the host server. The server connection information is stored in a list called servers_to_scan, which is accessible from the main tls_scan function. The function will return a string error message if the connection failed.

  * *ip_address*: string IP address to scan

  * *str_host*: string hostname (SNI)

  * *servers_to_scan*: empty list to contain server connection information

  * *port_to_scan*: int port to scan

  * *return*: string “success” or error message

**def addScanRequests(scanner, servers_to_scan, commands)**

AddScanRequests queues and runs the requested scan commands. This step can take a little while, especially if vulnerability tests are included. The scanner object is updated to hold the results of the scan requests.

  * *scanner*: object of sslyze Scanner() class

  * *servers_to_scan*: list of open connections

  * *commands*: list of string commands

  * *return*: None

**def getCertificateResults(certificate)**

GetCertificateResults is a helper function dedicated to building the dictionary for the certificate data. Each certificate in the deployment chain (usually 2) is sent to this function and parsed for serial numbers, public key, validity dates, signature hash algorithms, and subject alternative names. The

  * *certificate*: string literal certificate in PEM format

  * *return*: dictionary of certificate data

modules/getdns.py
^^^^^^^^^^^^^^^^^

**def get_dns(hostname, all_checks)**

Get_dns performs a quick DNS check on the specified hostname. The ‘A’ records are always collected because the IP addresses for the hostname are stored there. If all_checks is set to true, records for CAA, TXT and MX records will also be collected by the getDNSRecord helper function. The dictionary of DNS data is returned.

  * *hostname*: string hostname

  * *all_checks*: Boolean variable, true if all DNS checks should be performed, false if they should not be

  * *return*: dictionary of DNS data

**def getDNSRecord(hostname, record_type)**

GetDNSRecord specifically collects the DNS records for a specified record type using the dns.resolver Python library. The list of collected records is returned.

  * *hostname*: string hostname

  * *record_type*: string record type (A, CAA, TXT, MX)

  * *return*: list of records

modules/gethttp.py
^^^^^^^^^^^^^^^^^^

**def get_http(ip_address, hostname, int_port, usetls, http_pages)**

Get_http has three main purposes: 1. check if the server automatically reroutes a port 80 connection (HTTP) to a port 443 connection (HTTPS), 2. follow redirects for the hostname, and 3. collects HTTP header information for the hostname. Connections are created using the http.client library, and redirects either generate a 200 status or terminate after 10 loops.

  * *ip_address*: string IP address to connect to

  * *hostname*: string hostname

  * *int_port*: int port to connect to

  * *usetls*: Boolean, true if function should connect using HTTPS (TLS), false for HTTP

  * *http_pages*: Boolean if HTTP pages information should be included in output

  * *return*: [host, path, http_to_https redirection], dictionary of HTTP data

**def split_location(location)**

Split_location receives a header location and splits it into protocol, domain name and path.

  * *location*: header location

modules/gethttp2.py
^^^^^^^^^^^^^^^^^^^

**def check_http2(domain_name, conn_port)**

Check_http2 will return true if the selected application-layer protocol negotiation is h2 (HTTP/2), and false otherwise.

  * *domain_name*: string hostname

  * *conn_port*: port to connect to

  * *return*: Boolean true if port supports HTTP2, false if not