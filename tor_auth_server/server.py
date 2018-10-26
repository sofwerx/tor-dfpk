from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import re


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


AUTH_FILENAME = 'auth_credentials.dat'
AUTH_CREDENTIALS = []

# Regex used to check if a string is indeed base64
BASE64_REGEX_VALIDATOR = r'^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$'
BASE64_REGEX_VALIDATOR = re.compile(BASE64_REGEX_VALIDATOR)


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
        elif auth_header.startswith('Basic '):
            auth_token = auth_header.split(' ')[1]
            print(auth_token)
            if auth_token in AUTH_CREDENTIALS:
                print('Authenticated user connected, sending TOR config')
                self.send_response(200)
                self.send_tor_config_data()
            else:
                self.send_auth_request()
                self.wfile.write(b'Invalid auth credentials, try again')
        else:
            self.send_auth_request()
            self.wfile.write(b'Invalid auth credentials, try again')


def is_valid_base64(content):
    return BASE64_REGEX_VALIDATOR.match(content) is not None


def read_auth_file():
    with open(AUTH_FILENAME, 'r') as f:
        for line in f.readlines():
            if line:
                line = line.strip()
                if is_valid_base64(line):
                    AUTH_CREDENTIALS.append(line)
                else:
                    print(f'auth credential {line} ignored, must be valid base64')


def run():
    print('Starting TOR Auth server')

    read_auth_file()

    server_address = ('127.0.0.1', 8080)
    httpd = HTTPServer(server_address, TorAuthServer)

    message = 'Server is running on {}:{}' \
        .format(server_address[0], server_address[1])

    print(message)

    httpd.serve_forever()


if __name__ == '__main__':
    run()
