#!/usr/bin/env python

import os
import socket
import ssl
import sys
from weblib import base_handler
from weblib import threaded_http
from threading import Thread


def serve_on_port():
    try:
        cert_path = 'weblib/server.pem'
        server = threaded_http.ThreadingHTTPServer(
            ("0.0.0.0", 443), base_handler.GetHandler)
        server.socket = ssl.wrap_socket(
            server.socket, certfile=cert_path, server_side=True)
        server.serve_forever()
    except socket.error:
        print "[*][*] Error: Port 443 is currently in use!"
        print "[*][*] Error: Please restart when port is free!\n"
        sys.exit()
    return


try:
    print "[*] Starting web (https) server..."
    # bind to all interfaces
    Thread(target=serve_on_port).start()
    print "[*] Web server is currently running"
    print "[*] Type \"kill -9 " + str(os.getpid()) + "\" to stop the web server."
# handle keyboard interrupts
except KeyboardInterrupt:
    print "[!] Rage quiting, and stopping the web server!"
