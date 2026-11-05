"""Approves a review on Speculos through its REST API.

Waits for a screen starting with FIRST, presses right until a screen starting
with TARGET, then presses both buttons on it:

    python3 approve.py Review "Sign transaction"

Start it before the program sending the request and wait for that program to
exit: this script only presses buttons, so it never competes with the
program's connection to the emulator.
"""

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
    first, target = sys.argv[1], sys.argv[2]

    deadline = time.monotonic() + START_TIMEOUT
    while not screen().startswith(first):
        if time.monotonic() > deadline:
            sys.exit(f"review did not start; screen: {screen()}")
        time.sleep(0.1)

    for _ in range(MAX_PRESSES):
        if screen().startswith(target):
            press("both")
            return
        press("right")
    sys.exit(f"{target!r} not found; screen: {screen()}")


if __name__ == "__main__":
    main()
