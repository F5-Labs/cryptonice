# cryptonice
# gethttp.py

import http.client
import ssl


def split_location(location):
    """
    Receives a new header location and splits it into the protocol, domain name and path
    :param location: string url (ie https://www.google.com/us/home)
    :return: location split into protocol, domain and path, or the entire location if errors in splitting occurred
    """
    try:
        str_protocol = (location.split('//')[0]).replace(":", "")
        str_url = location.split('//')[1]
        str_host = str_url.split('/', 1)[0]
        try:
            str_path = "/" + str_url.split('/', 1)[1]
            # print(str_path)
        except:
            str_path = ""
        return [str_protocol, str_host, str_path]

    except:
        return [location]


def get_http(ip_address, hostname, int_port, usetls, http_pages, force_redirect):
    if usetls:
        print(f'Connecting to port {int_port} using HTTPS')
    else:
        print(f'Connecting to port {int_port} using HTTP')

    """
    Checks to see if a domain redirects from port 80 to 443 (http to https protocol), and performs necessary
    redirections as specified by user
    :param http_pages: boolean variable to include HTTP Pages data or not in output
    :param usetls: boolean variable on if TLS can be used (ie make an HTTPS connection)
    :param hostname: domain name to redirect
    :param int_port: port to try connecting to
    :return: updated domain, path and boolean value marking switch from http to https
    """
    b_httptohttps = False
    str_host = hostname
    str_path = '/'

    # DW Changed default behaviour to always perform HTTP > HTTPS redirect check
    if True:
        ###############################################################################################
        # First check for HTTP > HTTPS redirects (so we force port 80 regardless of what the target is)
        #print(f'Checking for HTTP > HTTPS redirects...')
        int_redirect = 0
        int_status = 0

        while int_redirect < 10 and int_status != 200:
            int_redirect = int_redirect + 1
            prev_host = str_host

            conn = http.client.HTTPConnection(ip_address, 80, timeout=5)
            try:
                conn.request('GET', str_path, headers={"Host": hostname})
                res = conn.getresponse()
            except:
                return "ERROR: Connection failed", "ERROR: Connection to server failed"

            # If we get a redirection then update the new path (str_path) to wherever we're being told to go by the
            # LOCATION header Need to make sure we close the connection so we can then re-open it to the new site
            int_status = res.status
            if 300 < int_status < 400:
                str_location = res.getheader('Location')

                if "https://" in str_location:
                    b_httptohttps = True
                    int_redirect = 10  # no more processing
                else:
                    str_location = split_location(res.getheader('Location'))
                    str_protocol = str_location[0]
                    str_host = str_location[1]
                    str_path = str_location[2]
            else:
                pass
                #print(f'{int_redirect}: Finished. Status = {int_status}')

            conn.close()
            """
            except:
                # Failed to connect to port - redirects will never work
                print('Redirect attempts failed. Reverting to original host and port.')
                return "ERROR: Connection failed"
            """
        ###############################################################################################

    ###############################################################################################
    # Now we check for redirects on the actual target port...
    # Simple logic to follow redirects, but set a limit so we don't loop forever
    int_redirect = 0
    int_status = 0

    # Reset our variables to their original target values
    str_host = hostname
    str_path = "/"

    while int_redirect < 10 and int_status != 200:
        int_redirect = int_redirect + 1
        prev_host = str_host
        prev_path = str_path

        #DEBUG
        #print(f'{int_redirect}: Checking {str_host} at {str_path}')

        if usetls:
            # print(f'Attempting HTTPS connection to {ip_address} using SNI of {str_host}')
            try:
                conn = http.client.HTTPSConnection(str_host, int_port, timeout=5, context=ssl._create_unverified_context())
                conn.request("GET", str_path)
                res = conn.getresponse()
                conn.close()
            except ssl.SSLError:
                # If we get legacy and unsupported ciphers then for these HTTP checks we're just going to fail
                # The SSLyze functions will catch and report on legacy and broken protocols...
                return [str_host, str_path, b_httptohttps], []
        else:
            try:
                # print(f'Attemping HTTP connection to {ip_address} using HOST header of {str_host}')
                conn = http.client.HTTPConnection(ip_address, int_port, timeout=5)
                conn.request('GET', str_path, headers={"Host": hostname})
                res = conn.getresponse()
                conn.close()
            except:
                return [str_host, str_path, b_httptohttps], []

        if force_redirect:
            # If we get a redirection then update the new path (str_path) to wherever we're being told to go by the
            # LOCATION header Need to make sure we close the connection so we can then re-open it to the new site
            int_status = res.status
            if 300 < int_status < 400:
                str_location = res.getheader('Location')
                # DEBUG
                # print(f'{int_redirect}: Found new location at {str_location}')
                str_location = split_location(res.getheader('Location'))

                # if our split function only returns 1 element it's because there has been an error,
                # probably caused by a lack of protocol prefix or domain name in the new location
                if len(str_location) == 1:
                    str_host = prev_host
                    str_path = str_location[0]
                else:
                    str_protocol = str_location[0]
                    str_host = str_location[1]
                    str_path = str_location[2]

                # Some redirects will not specify a new domain name
                # This prevents us having an empty host if only a new path is specified
                if str_host == "":
                    str_host = prev_host

            # If for some reason we keep getting redirects to the same host and path, then lets exit this loop early...
            if str_host == prev_host and str_path == prev_path:
                int_redirect = 10

        else:
            int_redirect = 10

    ######################################################################################
    # Get HTTP header data on same connection
    connection_data = {}
    host_data = {}
    header_data = {}
    cookie_data = {}

    host_data.update({'hostname': str_host})
    host_data.update({'path': str_path})
    connection_data.update({'Connection': host_data})

    print(f'Reading HTTP headers for {str_host}')

    # Standard headers
    header_data.update({'Access-Control-Allow-Origin': res.getheader('Access-Control-Allow-Origin')})
    header_data.update({'Access-Control-Allow-Origin': res.getheader('Access-Control-Allow-Origin')})
    header_data.update({'Access-Control-Allow-Credentials': res.getheader('Access-Control-Allow-Credentials')})
    header_data.update({'Access-Control-Expose-Headers': res.getheader('Access-Control-Expose-Headers')})
    header_data.update({'Access-Control-Max-Age': res.getheader('Access-Control-Max-Age')})
    header_data.update({'Access-Control-Allow-Methods': res.getheader('Access-Control-Allow-Methods')})
    header_data.update({'Access-Control-Allow-Headers': res.getheader('Access-Control-Allow-Headers')})
    header_data.update({'Allow': res.getheader('Allow')})

    alt_svc_data = {}
    alt_svc = res.getheader('Alt-Svc')
    if alt_svc is not None:
        result = alt_svc.split("; ")
        if result[0] == "clear":
            header_data.update({'Alt-Svc': 'clear'})
        else:
            for pair in result:
                key = (pair.split("="))[0]
                value = (pair.split("="))[1].strip("\"")
                alt_svc_data.update({key: value})
            header_data.update({'Alt-Svc': alt_svc_data})

    header_data.update({'Content-Encoding': res.getheader('Content-Encoding')})
    header_data.update({'Content-Language': res.getheader('Content-Language')})
    header_data.update({'Content-Length': res.getheader('Content-Length')})
    header_data.update({'Content-Location': res.getheader('Content-Location')})
    header_data.update({'Content-Type': res.getheader('Content-Type')})
    header_data.update({'ETag': res.getheader('ETag')})
    header_data.update({'Location': res.getheader('Location')})
    header_data.update({'Origin': res.getheader('Origin')})
    header_data.update({'Public-Key-Pins': res.getheader('Public-Key-Pins')})
    header_data.update({'Server': res.getheader('Server')})
    header_data.update({'Strict-Transport-Security': res.getheader('Strict-Transport-Security')})
    header_data.update({'Transfer-Encoding': res.getheader('Transfer-Encoding')})
    header_data.update({'Tk': res.getheader('Tk')})
    header_data.update({'Upgrade': res.getheader('Upgrade')})
    header_data.update({'Via': res.getheader('Via')})
    header_data.update({'WWW-Authenticate': res.getheader('WWW-Authenticate')})
    header_data.update({'X-Frame-Options': res.getheader('X-Frame-Options')})

    # Non-standard
    header_data.update({'Content-Security-Policy': res.getheader('Content-Security-Policy')})
    header_data.update({'X-Content-Security-Policy': res.getheader('X-Content-Security-Policy')})
    header_data.update({'X-WebKit-CSP': res.getheader('X-WebKit-CSP')})
    header_data.update({'X-Powered-By': res.getheader('X-Powered-By')})
    header_data.update({'X-XSS-Protection': res.getheader('X-XSS-Protection')})

    connection_data.update({'Headers': header_data})

    # The server may not return any cookies, so we need to see what there is
    try:
        cookies = res.getheader('Set-Cookie').split("; ")
        for things in cookies:
            str_cookie_name = (things.split("="))[0]
            try:
                str_cookie_value = (things.split("="))[1]
            except:
                str_cookie_value = 'null'
            # data from sites that have multiple cookies are not all being recorded
            cookie_data.update({str_cookie_name: str_cookie_value})
        connection_data.update({'Cookies': cookie_data})
    except:
        connection_data.update({'Cookies': ''})

    # Read the main body of the page (the HTML)
    data = res.read()

    # Include page data in output if requested
    if http_pages:
        connection_data.update({'Page': str(data)})

    conn.close()

    return [str_host, str_path, b_httptohttps], connection_data
