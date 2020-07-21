# cryptonice
# checkport.py

import socket
import http.client
import ssl


def port_open(hostname, port):
    #print('\nOpen port checks')
    #print('------------------------------')
    """
    Check status of a port and return simple True/False
    Also check for TLS handshake
    """
    open_port = False
    open_tls = True  # change to False later

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock_result = sock.connect_ex((hostname, port))

        if sock_result == 0:
            open_port = True
            try:
                conn = http.client.HTTPSConnection(hostname, port, timeout=3, context=ssl._create_unverified_context())
                conn.request("GET", "/")
                res = conn.getresponse()
                conn.close()
                open_tls = True
            except:
                pass

    return open_port, open_tls


if __name__ == "__main__":
    port_open()
