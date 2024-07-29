import http.server
import socketserver

# Define a custom HTTP request handler class that logs messages to a file
class LoggingHTTPHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        with open("/home/mininet/mininet/mininet/DACNTT2_DDos_ML/FinalVersion/mininet/http_server.log", "a") as log_file:
            log_file.write("%s - - [%s] %s\n" % (self.client_address[0],
                                                 self.log_date_time_string(),
                                                 format % args))

PORT = 80

# Create a TCP server instance with the custom logging handler
with socketserver.TCPServer(("", PORT), LoggingHTTPHandler) as httpd:
    httpd.serve_forever()
