#!/usr/bin/python3
"""
Simple webserver that reacts on events published by Sipgate.io.
Can be used to call Home Assistant services via DTMF codes.
https://www.sipgate.io
https://github.com/sipgate/sipgate.io
"""
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl
import socketserver
import urllib.parse
import logging
import base64
from xml.dom.minidom import Document
import signal
import actions

logging.basicConfig(level=logging.INFO)

### Customizable globals
ALLOWED_CALLERS = {
    "4911223344": {
        "dtmf": {
            123456: actions.toggle_light
        }
    },
    "4922334455": {
        "dtmf": {
            123456: actions.toggle_light
        }
    }
}
BLOCKED_CALLERS = [
    "4933445566"
]
LISTENIP = "0.0.0.0"
LISTENPORT = 3000
# Set the paths to a certificate and the key if you're using SSL, e.g "/etc/ssl/certs/mycert.pem"
# Limitations: https://github.com/sipgate/sipgate.io#http-vs-https
SSL_CERTIFICATE = None
SSL_KEY = None
# The URL Sipgate.io will communicate with
BASEURL = "http://example.yourdomain.com:3000"
# Set a username and password to allow access to the API
CREDENTIALS = "username:secret"
# Audio files to playback (https://github.com/sipgate/sipgate.io#play)
HELLOFILE = "hello.wav"
OKFILE = "ok.wav"
ERRORFILE = "error.wav"

### Internal globals
CALLS = {}
HTTPD = None
STATE_PENDING = 1
STATE_ACTIVE = 2

def signal_handler(sig, frame):
    global HTTPD
    logging.info("Got signal: %s. Shutting down server", str(sig))
    HTTPD.server_close()
    sys.exit(0)

def action_handler(callid, dtmf):
    logging.debug("action_handler")
    logging.debug(CALLS[callid]['caller'])
    logging.debug(CALLS[callid]['called'])
    logging.debug(dtmf)
    try:
        dtmfdict = ALLOWED_CALLERS[CALLS[callid]['caller']].get("dtmf", None)
        if not dtmfdict:
            logging.warning("No dtmf dict")
            return False
        logging.debug(dtmfdict)
        func = dtmfdict.get(dtmf, None)
        if not func:
            logging.warning("Function for %s not found" % dtmf)
            return False
        return func()
    except Exception as err:
        logging.error("Exception while executing action: %s" % err)
    return False

class Sipgate(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        logging.info("%s - %s" % (self.client_address[0], format % args))
        return

    def do_AUTHHEAD(self):
        logging.info("Requesting authorization")
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm=\"sipgate.io\"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        global CREDENTIALS
        authorization = self.headers.get('Authorization', None)
        if authorization is None:
            self.do_AUTHHEAD()
            self.wfile.write(bytes('401 Forbidden', 'utf-8'))
        elif authorization == 'Basic %s' % CREDENTIALS.decode('utf-8'):
            try:
                if self.path.endswith(".wav"):
                    with open(self.path.split('/')[-1], 'rb') as fptr:
                        self.send_response(200)
                        self.send_header('Content-type', 'audio/wav')
                        self.end_headers()
                        self.wfile.write(fptr.read())
                        return
                else:
                    self.send_error(404, 'File Not Found: %s' % self.path)

            except IOError:
                self.send_error(404, 'File Not Found: %s' % self.path)
        else:
            self.do_AUTHHEAD()
            self.wfile.write(bytes('Authentication required', 'utf-8'))
            pass

    def do_POST(self):
        global CREDENTIALS, CALLS
        authorization = self.headers.get('Authorization', None)
        if authorization is None:
            self.do_AUTHHEAD()
            self.wfile.write(bytes('no auth header received', 'utf-8'))
        elif authorization == 'Basic %s' % CREDENTIALS.decode('utf-8'):
            logging.debug("Calls: %s", CALLS)
            req = urllib.parse.urlparse(self.path)
            length = int(self.headers['Content-Length'])
            data = urllib.parse.parse_qs(self.rfile.read(length).decode('utf-8'))
            logging.debug("data: %s", data)
            event = data.get("event", [])[0]
            logging.info("Event: %s", event)
            if event in ["newCall", "answer", "hangup"]:
                caller = data.get("from")[0]
                logging.info("Caller: %s", caller)
                called = data.get("to")[0]
                logging.debug("Called: %s", called)
                direction = data.get("direction")[0]
                logging.info("Direction: %s", direction)
                callid = data.get('callId')[0]
                if caller in BLOCKED_CALLERS:
                    logging.warning("Rejecting")
                    doc = Document()
                    response = doc.createElement('Response')
                    reject = doc.createElement('Reject')
                    response.appendChild(reject)
                    doc.appendChild(response)
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/xml')
                    self.end_headers()
                    self.wfile.write(doc.toxml().encode('utf-8'))
                elif caller in ALLOWED_CALLERS.keys():
                    logging.debug("Allowed caller")
                    if event == "hangup" and CALLS.get(callid):
                        logging.info("Finishing call: %s", callid)
                        CALLS.pop(callid)
                    elif event == "newCall":
                        logging.debug("New call: %s", callid)
                        CALLS[callid] = {
                            'state': STATE_PENDING,
                            'caller': caller,
                            'called': called
                        }
                        logging.debug("Added call ID: %s" % callid)
                        logging.debug("Calls: %s" % CALLS)
                        doc = Document()
                        response = doc.createElement('Response')
                        gather = doc.createElement('Gather')
                        gather.setAttribute('onAnswer', BASEURL)
                        gather.setAttribute('onHangup', BASEURL)
                        gather.setAttribute('onData', BASEURL)
                        gather.setAttribute('onHangup', BASEURL)
                        gather.setAttribute('maxDigits', "6")
                        gather.setAttribute('timeout', "10")
                        url = doc.createTextNode("%s/%s" % (BASEURL, HELLOFILE))
                        gather.appendChild(url)
                        response.appendChild(gather)
                        doc.appendChild(response)
                        self.send_response(200)
                        self.send_header('Content-Type', 'application/xml')
                        self.end_headers()
                        self.wfile.write(doc.toxml().encode('utf-8'))
                        return
                    elif event == "answer" and CALLS.get(callid)['state'] == STATE_PENDING:
                        logging.debug("Call answered: %s", callid)
                        CALLS[callid]['state'] = STATE_ACTIVE
                        # Response to this is being discarded
                        doc = Document()
                        self.send_response(200)
                        self.send_header('Content-Type', 'application/xml')
                        self.end_headers()
                        self.wfile.write(doc.toxml().encode('utf-8'))
                        return
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write("http://xkcd.com/353/".encode('utf-8'))
                else:
                    logging.debug("Unknown bot not blacklisted caller: %s", caller)
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write("http://xkcd.com/353/".encode('utf-8'))
                    return
            elif event == "dtmf":
                callid = data.get('callId')[0]
                if not CALLS.get(callid):
                    logging.warning("No active call for Callid: %s", callid)
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write("http://xkcd.com/353/".encode('utf-8'))
                    return
                if CALLS.get(callid)['state'] == STATE_ACTIVE:
                    logging.debug("Call: %s", callid)
                    dtmf = data.get("dtmf", None)
                    if dtmf:
                        doc = Document()
                        response = doc.createElement('Response')
                        play = doc.createElement('Play')
                        if action_handler(callid, int(dtmf[0])):
                            oke = doc.createElement('Url')
                            url = doc.createTextNode("%s/%s" % (BASEURL, OKFILE))
                            oke.appendChild(url)
                            play.appendChild(oke)
                        else:
                            err = doc.createElement('Url')
                            url = doc.createTextNode("%s/%s" % (BASEURL, ERRORFILE))
                            err.appendChild(url)
                            play.appendChild(err)
                        response.appendChild(play)
                        doc.appendChild(response)
                        self.send_response(200)
                        self.send_header('Content-Type', 'application/xml')
                        self.end_headers()
                        self.wfile.write(doc.toxml().encode('utf-8'))
                        return

                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write("http://xkcd.com/353/".encode('utf-8'))
                    return
                else:
                    logging.debug("Finishing call: %s", callid)
                    CALLS.pop(callid)
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write("http://xkcd.com/353/".encode('utf-8'))
                    return
            else:
                logging.warning("Unknown event")
                self.send_response(200)
                self.end_headers()
                self.wfile.write("http://xkcd.com/353/".encode('utf-8'))
        else:
            self.do_AUTHHEAD()
            self.wfile.write(bytes('Authentication required', 'utf-8'))
            pass

def main(args):
    global HTTPD, CREDENTIALS, BASEURL
    server_address = (LISTENIP, LISTENPORT)
    BASEURL = ("//%s@" % CREDENTIALS).join(BASEURL.split("//"))
    CREDENTIALS = base64.b64encode(bytes(CREDENTIALS, "utf-8"))
    if not SSL_CERTIFICATE:
        HTTPD = HTTPServer(server_address, Sipgate)
    else:
        HTTPD = socketserver.TCPServer(server_address, Sipgate)
        HTTPD.socket = ssl.wrap_socket(HTTPD.socket,
                                       certfile=SSL_CERTIFICATE,
                                       keyfile=SSL_KEY,
                                       server_side=True)
    logging.info('Listening on: %s://%s:%i' % ('https' if SSL_CERTIFICATE else 'http',
                                               LISTENIP,
                                               LISTENPORT))

    HTTPD.serve_forever()

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    main(sys.argv[1:])
