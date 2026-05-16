#!/usr/bin/env python3
"""
Simple HTTP server to serve your frontend HTML
Run this in a separate terminal
"""

import http.server
import socketserver

PORT = 3000

Handler = http.server.SimpleHTTPRequestHandler

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print(f"Frontend server running at http://localhost:{PORT}")
    print(f"Make sure Flask backend is running on http://localhost:5000")
    print("Press Ctrl+C to stop")
    httpd.serve_forever()