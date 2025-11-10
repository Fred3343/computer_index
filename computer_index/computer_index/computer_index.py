#!/usr/bin/env python3
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import argparse, os

parser = argparse.ArgumentParser(description="Simple static server for your site.")
parser.add_argument("--port", "-p", type=int, default=8000, help="listening port")
parser.add_argument("--dir", "-d", default=".", help="site root directory")
args = parser.parse_args()

os.chdir(args.dir)
server = ThreadingHTTPServer(("0.0.0.0", args.port), SimpleHTTPRequestHandler)
print(f"Serving {os.getcwd()} at http://0.0.0.0:{args.port} (Ctrl+C to quit)")
try:
    server.serve_forever()
except KeyboardInterrupt:
    pass
