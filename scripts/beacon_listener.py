"""
Lab-only traffic generator for building the beaconing detector's training/test data,
per docs/10_DATASET_GENERATION.md and docs/decisions.md Phase 6.
Never run against anything outside our own isolated lab network.
"""

import argparse
import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

class BeaconHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/checkin':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'OK\n')
            
            # Log check-in to stdout with timestamp and source IP
            ts = datetime.datetime.now().isoformat()
            src_ip = self.client_address[0]
            print(f"[{ts}] Check-in received from {src_ip}")
        else:
            self.send_response(404)
            self.end_headers()

    # Suppress default HTTP server logging to keep stdout clean for our custom log
    def log_message(self, format, *args):
        pass

def main():
    parser = argparse.ArgumentParser(description="Beacon Listener (Lab Only)")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on (default 8080)")
    args = parser.parse_args()

    server_address = ('0.0.0.0', args.port)
    server = HTTPServer(server_address, BeaconHandler)
    
    print(f"Listening for beacons on 0.0.0.0:{args.port} (endpoint: /checkin)...")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping listener...")
    finally:
        server.server_close()

if __name__ == "__main__":
    main()
