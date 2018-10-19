from http.server import BaseHTTPRequestHandler, HTTPServer
import json


# torrc configuration data which tells clients how to connect to the private
# Tor network.
#
# This is just placeholder data until I know the tor server config or have a
# way to read it off disk.
TORRC_CONFIG_DATA = {
    'DirAuthority': {
        'nickname': 'test_private',
        'ipv4': '133.713.371.337',
        'port': 1234,
        'fingerprint': 'afdsafdasf'
    },
}


class TorAuthServer(BaseHTTPRequestHandler):
    def send_auth_request(self):
        print('Unathorized user request, sending WWW-Authenticate headers')
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm=\"Tor auth\"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def send_tor_config_data(self):
        json_data = json.dumps(TORRC_CONFIG_DATA)
        self.wfile.write(str.encode(json_data))

    def do_GET(self):
        auth_header = self.headers.get('Authorization')
        if auth_header is None:
            # User is not logged in and must post with basic auth headers
            self.send_auth_request()
            self.wfile.write(b'Please enter your username and password')
        elif auth_header == 'Basic dGVzdDp0ZXN0':
            # dGVzdDp0ZXN0 is base64 for test:test
            # TODO: parse out the base64 string and authenticate it.
            print('Authenticated user connected, sending TOR config')
            self.send_response(200)
            self.send_tor_config_data()
        else:
            self.send_auth_request()
            self.wfile.write(b'Invalid auth credentials, try again')


def run():
    print('Starting TOR Auth server')
    server_address = ('127.0.0.1', 8080)
    httpd = HTTPServer(server_address, TorAuthServer)

    message = 'Server is running on {}:{}' \
        .format(server_address[0], server_address[1])

    print(message)

    httpd.serve_forever()


if __name__ == '__main__':
    run()
