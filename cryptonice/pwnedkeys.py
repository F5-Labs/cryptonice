# cryptonice
# pwndkeys.py

import http.client
import ssl

# import warnings
import pkg_resources
from bs4 import BeautifulSoup


def check_key(cert_fingerprint):

    connection = http.client.HTTPSConnection("v1.pwnedkeys.com", 443, timeout=5, context=ssl._create_unverified_context())
    connection.request("GET", "/8d296b2f6c9e3f8913c7ac3689c5ce116943c62ab6640a759926895a2137a79c")
    response = connection.getresponse()
    http_status = response.status
    connection.close()

    if http_status == 200:
        keystatus = {"pwned": True}
    else:
        keystatus =  {"pwned": False}

    return keystatus
