#!/bin/bash

set -e

# The IOTA Ledger app release whose Nano S Plus build Speculos runs
LEDGER_APP_VERSION="1.0.1"
SPECULOS_IMAGE="ghcr.io/ledgerhq/speculos:v0.27.1"
CONTAINER_NAME="speculos"
APDU_PORT=9999
API_PORT=5001
APP_DIR="$(pwd)/target/speculos/ledger-app-iota-v$LEDGER_APP_VERSION"

if [ "$1" == "start" ]; then
    if [ ! -f "$APP_DIR/nanosplus/iota" ]; then
        download_url="https://github.com/iotaledger/ledger-app-iota/releases/download/ledger-app-iota-v$LEDGER_APP_VERSION/nanosplus.tar.gz"
        echo "Downloading the IOTA app from $download_url"
        mkdir -p "$APP_DIR"
        curl --silent --fail --location "$download_url" | tar -xz -C "$APP_DIR"
    fi

    # Remove a previous emulator, whose app may have exited
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

    echo "Starting Speculos..."
    docker run -d --name "$CONTAINER_NAME" \
        -p "$APDU_PORT:$APDU_PORT" -p "$API_PORT:$API_PORT" \
        -v "$APP_DIR/nanosplus:/speculos/apps" \
        -e "SPECULOS_APPNAME=IOTA:$LEDGER_APP_VERSION" \
        "$SPECULOS_IMAGE" --model nanosp --display headless \
        --apdu-port "$APDU_PORT" --api-port "$API_PORT" apps/iota

    echo "Waiting for Speculos to be ready..."
    success=false
    for _ in {1..60}; do
        sleep 1
        if curl --silent --fail "http://127.0.0.1:$API_PORT/events?currentscreenonly=true" >/dev/null 2>&1; then
            success=true
            break
        fi
    done
    if ! $success; then
        echo "Speculos did not start after 60 seconds"
        docker logs "$CONTAINER_NAME" 2>&1 || echo "(no container logs)"
        exit 1
    fi

    echo "Speculos started: APDU port $APDU_PORT, API and web interface at http://127.0.0.1:$API_PORT"
    echo "To stop, run: $0 stop"

elif [ "$1" == "stop" ]; then
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || echo "Speculos not running"
    echo "Speculos stopped."

elif [ "$1" == "logs" ]; then
    docker logs -f "$CONTAINER_NAME"

else
    echo "Usage: $0 start|stop|logs"
    echo "  start: Start Speculos with the IOTA app on a Nano S Plus"
    echo "  stop:  Stop Speculos"
    echo "  logs:  View the Speculos logs (follow mode)"
fi
