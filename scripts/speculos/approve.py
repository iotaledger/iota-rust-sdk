"""Approves a review on Speculos through its REST API.

Waits for the first screen of the review, presses right until the screen
that approves it, then presses both buttons on that screen. Both are given as
the start of the screen's text:

    python3 approve.py Review "Sign transaction"

Start it before the program sending the request and wait for that program to
exit: this script only presses buttons, so it never competes with the
program's connection to the emulator.
"""

import argparse
import json
import os
import sys
import time
import urllib.request

API = os.environ.get("SPECULOS_API", "http://127.0.0.1:5001")
# Seconds to wait for the review to start, which covers the program's setup
START_TIMEOUT = float(os.environ.get("SPECULOS_APPROVE_TIMEOUT", "300"))
MAX_PRESSES = 80


def screen():
    with urllib.request.urlopen(f"{API}/events?currentscreenonly=true") as response:
        return " | ".join(event["text"] for event in json.load(response)["events"])


def press(button):
    request = urllib.request.Request(
        f"{API}/button/{button}",
        data=b'{"action":"press-and-release"}',
        method="POST",
    )
    urllib.request.urlopen(request).read()
    time.sleep(0.6)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("review_screen", help="start of the review's first screen")
    parser.add_argument("approve_screen", help="start of the screen that approves the review")
    args = parser.parse_args()

    deadline = time.monotonic() + START_TIMEOUT
    while not screen().startswith(args.review_screen):
        if time.monotonic() > deadline:
            sys.exit(f"review did not start; screen: {screen()}")
        time.sleep(0.1)

    for _ in range(MAX_PRESSES):
        if screen().startswith(args.approve_screen):
            press("both")
            return
        press("right")
    sys.exit(f"{args.approve_screen!r} not found; screen: {screen()}")


if __name__ == "__main__":
    main()
