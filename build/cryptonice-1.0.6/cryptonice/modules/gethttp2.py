# cryptonice
# gethttp2.py

# For ALPN and NPN information:
# https://docs.python.org/3/library/ssl.html

import socket
import ssl

from urllib.parse import urlparse

socket.setdefaulttimeout(5)

headers = {"user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 "
                         "Safari/537.36"}


def check_http2(domain_name, conn_port):
    print('Looking for HTTP/2')
    try:
        # This fails if HOST does not include HTTPS://
        # We will need to check for this and either add HTTPS:// manually, or remove the dependency on it
        updated_dom = 'https://' + domain_name
        HOST = urlparse(updated_dom).netloc
        PORT = conn_port

        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(['h2', 'spdy/3', 'http/1.1'])

        conn = ctx.wrap_socket(
            socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=HOST)
        conn.connect((HOST, PORT))

        pp = conn.selected_alpn_protocol()

        if pp == "h2":
            return {"http2": True}
        else:
            return {"http2": False}
    except Exception as e:
        #return f'Error with HTTP/2 support check: {e.__str__()}'
        #return f'\nError with HTTP/2 test'
        return False
