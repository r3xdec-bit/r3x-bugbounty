"""
Local Mock Vulnerable Target Server for Automated Testing
Simulates typical Web & API misconfigurations (OWASP Top 10) in an isolated, safe localhost environment.
"""
import http.server
import threading
import time

class VulnerableHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Silence standard HTTP access logs during test runs
        pass

    def do_GET(self):
        # 1. Base route with missing security headers & verbose server banner
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "Apache/2.4.49 (Unix) OpenSSL/1.1.1")
            self.send_header("X-Powered-By", "PHP/8.0.1")
            self.send_header("Set-Cookie", "sessionid=xyz123456789; Path=/") # Missing HttpOnly & Secure
            self.end_headers()
            html = """<!DOCTYPE html>
            <html>
            <head><title>Vulnerable Mock App</title></head>
            <body>
                <h1>Vulnerable Test Target</h1>
                <script src="/static/app.js"></script>
            </body>
            </html>"""
            self.wfile.write(html.encode("utf-8"))

        # 2. CORS Misconfiguration Endpoint
        elif self.path == "/api/v1/user":
            origin = self.headers.get("Origin", "")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            if origin:
                # Vulnerable reflective CORS with credentials
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Credentials", "true")
            self.end_headers()
            self.wfile.write(b'{"user": "admin", "role": "superadmin"}')

        # 3. Exposed Swagger Schema
        elif self.path == "/swagger.json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"swagger": "2.0", "info": {"title": "Internal API", "version": "1.0"}}')

        # 4. JavaScript with routes and pattern matching tokens
        elif self.path == "/static/app.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            js_content = """
            const apiUrl = "/api/v1/user";
            const mockStripeKey = "pk_live_ABC123456789012345678901";
            console.log("App initialized with " + apiUrl);
            """
            self.wfile.write(js_content.encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()

class MockTargetServer:
    def __init__(self, port: int = 8999):
        self.port = port
        self.server = None
        self.thread = None

    def start(self):
        self.server = http.server.HTTPServer(("127.0.0.1", self.port), VulnerableHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.3)

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
