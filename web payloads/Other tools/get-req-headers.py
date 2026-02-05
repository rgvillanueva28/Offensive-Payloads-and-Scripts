from http.server import HTTPServer, BaseHTTPRequestHandler
import logging
import argparse

class LoggingHTTPRequestHandler(BaseHTTPRequestHandler):
    def log_request_headers_and_body(self):
        # Log request headers
        logging.info("Headers:")
        for header, value in self.headers.items():
            logging.info(f"{header}: {value}")
        
        # Log request body if present
        content_length = self.headers.get('Content-Length')
        if content_length:
            body = self.rfile.read(int(content_length)).decode('utf-8')
            logging.info("Body:")
            logging.info(body)
        else:
            logging.info("No body in request.")
    
    def handle_http_verb(self):
        # Log details for any HTTP verb
        logging.info(f"Received {self.command} request.")
        self.log_request_headers_and_body()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(f"{self.command} request received. Check server logs for details.".encode('utf-8'))

    def do_GET(self):
        self.handle_http_verb()
    
    def do_POST(self):
        self.handle_http_verb()
    
    def do_PUT(self):
        self.handle_http_verb()
    
    def do_DELETE(self):
        self.handle_http_verb()
    
    def do_PATCH(self):
        self.handle_http_verb()

    def do_HEAD(self):
        self.handle_http_verb()
    
    def do_OPTIONS(self):
        self.handle_http_verb()
    
    def do_TRACE(self):
        self.handle_http_verb()

    # Override unsupported HTTP methods
    def do_CONNECT(self):
        self.handle_http_verb()

if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Start a simple HTTP server that logs request headers and body.")
    parser.add_argument(
        "port", type=int, nargs="?", default=8080,
        help="Port number to start the HTTP server on (default: 8080)"
    )
    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
    server_address = ('', args.port)  # Bind to all interfaces on the specified port
    httpd = HTTPServer(server_address, LoggingHTTPRequestHandler)
    logging.info(f"Starting HTTP server on port {args.port}...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    logging.info("Shutting down server.")
    httpd.server_close()
