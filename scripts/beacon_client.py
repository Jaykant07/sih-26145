"""
Lab-only traffic generator for building the beaconing detector's training/test data,
per docs/10_DATASET_GENERATION.md and docs/decisions.md Phase 6.
Never run against anything outside our own isolated lab network.
"""

import argparse
import datetime
import random
import sys
import time

try:
    import requests
except ImportError:
    print("ERROR: The 'requests' library is not installed.")
    print("Please install it (e.g., pip install requests) or run from the project venv.")
    sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Beacon Client (Lab Only)")
    parser.add_argument("--listener-ip", type=str, 
                        help="Mandatory: IP address of the beacon listener (do NOT use 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, 
                        help="Port of the listener (default 8080)")
    parser.add_argument("--interval", type=float, default=60.0, 
                        help="Base sleep interval in seconds (default 60)")
    parser.add_argument("--jitter-pct", type=float, default=0.0, 
                        help="Jitter percentage as a decimal, e.g., 0.2 for 20%% (default 0.0)")
    
    args = parser.parse_args()

    # Enforce mandatory --listener-ip
    if not args.listener_ip:
        print("ERROR: --listener-ip is a mandatory argument.", file=sys.stderr)
        print("Do NOT default to localhost/127.0.0.1! Loopback traffic will not cross the interface Zeek is capturing on.", file=sys.stderr)
        sys.exit(1)

    url = f"http://{args.listener_ip}:{args.port}/checkin"
    print(f"Starting beacon client targeting: {url}")
    print(f"Configuration -> Interval: {args.interval}s, Jitter: {args.jitter_pct*100:.1f}%")
    print("Press Ctrl+C to stop.\n")

    while True:
        ts = datetime.datetime.now().isoformat()
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                print(f"[{ts}] Check-in SUCCESS")
            else:
                print(f"[{ts}] Check-in FAILED (HTTP {resp.status_code})")
        except requests.RequestException as e:
            # Catch all connection errors (e.g. ConnectionRefused, Timeout) and ignore crashes
            print(f"[{ts}] Check-in FAILED (Connection Error: {e})")

        # Calculate next sleep time with optional jitter
        jitter_val = args.interval * args.jitter_pct
        sleep_time = args.interval + random.uniform(-jitter_val, jitter_val)
        
        # Ensure sleep_time doesn't go below 0
        sleep_time = max(0.0, sleep_time)
        time.sleep(sleep_time)

if __name__ == "__main__":
    main()
