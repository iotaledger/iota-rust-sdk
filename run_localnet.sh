#!/bin/bash

set -e

CONFIG_PATH="./.github/actions/start-local-network/config.yaml"
COMPOSE_PATH="./.github/actions/start-local-network/gas_station_compose.yml"
COMPOSE_LOCAL_PATH="./.github/actions/start-local-network/gas_station_compose.local.yml"
CONFIG_BACKUP="$CONFIG_PATH.backup"
IOTA_LOG="iota_network.log"
IOTA_LOCALNET_BINARY="${2:-iota-localnet}"

if [ "$1" == "start" ]; then
    echo "Starting local IOTA network with gas station..."

    # Backup config file
    if [ -f "$CONFIG_BACKUP" ]; then
        echo "Backup already exists, skipping backup"
    else
        cp "$CONFIG_PATH" "$CONFIG_BACKUP"
        echo "Backed up config to $CONFIG_BACKUP"
    fi

    # Start PostgreSQL
    echo "Starting PostgreSQL..."
    docker start postgres || docker run -d --name postgres -e POSTGRES_PASSWORD=postgrespw -e POSTGRES_INITDB_ARGS="-U postgres" -p 5432:5432 postgres:15 -c max_connections=1000

    # Start IOTA network
    echo "Starting IOTA network..."
    RUST_LOG="info,consensus=warn,starfish_core=warn,iota_core=warn,fastcrypto_tbls=off,iota_indexer=warn,iota_data_ingestion_core=error,iota_graphql_rpc=warn" $IOTA_LOCALNET_BINARY start --force-regenesis --with-faucet --with-indexer --with-graphql --with-grpc $IOTA_START_EXTRA_ARGS >> "$IOTA_LOG" 2>&1 &
    IOTA_PID=$!

    # Use all 9's private key for gas station
    keyWithFlag="AJmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZ" # iotaprivkey1qzvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvejj8c0wa
    address="0xa7c2cf9d8f8d95ff69d7a598c49c77acc36253f496f064a533ad306879b40bfa"

    echo "Setting keypair in config..."
    sed -i.bak "s|<keypair>|$keyWithFlag|g" "$CONFIG_PATH" && rm "$CONFIG_PATH.bak"

    # On Linux, we use host networking (compose.local.yml) so both Redis and the
    # IOTA fullnode are accessible on localhost. On macOS, Docker Desktop doesn't
    # support host networking, so we use bridge networking with host.docker.internal.
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # Bridge networking: Redis is reachable via Docker DNS name, fullnode via host.docker.internal
        sed -i.bak "s|http://localhost:50051|http://host.docker.internal:50051|g" "$CONFIG_PATH" && rm "$CONFIG_PATH.bak"
    else
        # Host networking: everything is on localhost
        sed -i.bak "s|redis://redis:6379|redis://localhost:6379|g" "$CONFIG_PATH" && rm "$CONFIG_PATH.bak"
    fi

    echo "Waiting for network to start..."
    success=false
    for i in {1..60}; do
        sleep 1
        if curl --silent --fail -X POST http://127.0.0.1:9000 \
            -H 'Content-Type: application/json' \
            -d '{"jsonrpc":"2.0","id":1,"method":"iota_getLatestCheckpointSequenceNumber"}' >/dev/null 2>&1; then
            success=true
            break
        fi
    done
    if ! $success; then
        echo "Network did not start after 60 seconds"
        echo "Last 20 lines of $IOTA_LOG:"
        tail -20 "$IOTA_LOG" 2>/dev/null || echo "(no log file)"
        exit 1
    fi

    echo "Waiting for faucet to be ready..."
    success=false
    for i in {1..60}; do
        sleep 1
        if curl --silent --fail --location --request POST 'http://127.0.0.1:9123/gas' \
            --header 'Content-Type: application/json' \
            --data-raw "{\"FixedAmountRequest\":{\"recipient\":\"$address\"}}" >/dev/null 2>&1; then
            success=true
            break
        fi
    done
    if ! $success; then
        echo "Failed to request faucet coins after 60 seconds"
        echo "Last 20 lines of $IOTA_LOG:"
        tail -20 "$IOTA_LOG" 2>/dev/null || echo "(no log file)"
        exit 1
    fi

    echo "Starting Gas Station..."
    # Set gas station auth
    export GAS_STATION_AUTH=test
    if [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS: use default bridge networking (host networking not supported by Docker Desktop)
        docker compose -f "$COMPOSE_PATH" -p start-local-network up -d
    else
        # Linux: use host networking override
        docker compose -f "$COMPOSE_PATH" -f "$COMPOSE_LOCAL_PATH" -p start-local-network up -d
    fi

    echo "Waiting for gas station to be ready..."
    success=false
    for i in {1..60}; do
        sleep 1
        if curl --silent --fail http://localhost:9527/version >/dev/null 2>&1; then
            success=true
            break
        fi
    done
    if ! $success; then
        echo "Gas station did not become ready after 60 seconds"
        docker logs iota-gas-station 2>&1 || echo "(no container logs)"
        exit 1
    fi

    echo "Local network and gas station started successfully!"
    echo "IOTA PID: $IOTA_PID"
    echo "Logs are being written to $IOTA_LOG"
    echo "To view logs: $0 logs"
    echo "To view gas station logs: $0 gaslogs"
    echo "To stop, run: $0 stop"

elif [ "$1" == "stop" ]; then
    echo "Stopping local IOTA network and gas station..."

    # Stop gas station
    echo "Stopping Gas Station..."
    # Flush Redis data before stopping
    redis-cli FLUSHALL || echo "Could not flush Redis data"
    if [[ "$OSTYPE" == "darwin"* ]]; then
        docker compose -f "$COMPOSE_PATH" -p start-local-network down
    else
        docker compose -f "$COMPOSE_PATH" -f "$COMPOSE_LOCAL_PATH" -p start-local-network down
    fi

    # Remove Redis volume to clean persisted data
    echo "Removing Redis data volume..."
    docker volume rm start-local-network_redis_data || echo "Redis volume not found or already removed"

    # Stop IOTA network
    echo "Stopping IOTA network..."
    pkill -f "$IOTA_LOCALNET_BINARY start" || echo "IOTA process not found or already stopped"

    # Stop PostgreSQL
    echo "Stopping PostgreSQL..."
    docker stop postgres || echo "PostgreSQL not running"

    # Restore config
    if [ -f "$CONFIG_BACKUP" ]; then
        mv "$CONFIG_BACKUP" "$CONFIG_PATH"
        echo "Restored config from backup"
    else
        echo "No backup found, config may have been manually modified"
    fi

    # Clean up log file
    if [ -f "$IOTA_LOG" ]; then
        rm "$IOTA_LOG"
        echo "Removed log file $IOTA_LOG"
    fi

    echo "Local network and gas station stopped."

elif [ "$1" == "logs" ]; then
    if [ -f "$IOTA_LOG" ]; then
        tail -f "$IOTA_LOG"
    else
        echo "Log file $IOTA_LOG not found. Start the network first."
    fi

elif [ "$1" == "gaslogs" ]; then
    if [[ "$OSTYPE" == "darwin"* ]]; then
        docker compose -f "$COMPOSE_PATH" -p start-local-network logs -f
    else
        docker compose -f "$COMPOSE_PATH" -f "$COMPOSE_LOCAL_PATH" -p start-local-network logs -f
    fi

else
    echo "Usage: $0 start|stop|logs|gaslogs"
    echo "  start: Start the local IOTA network with gas station"
    echo "  stop:  Stop the local IOTA network and gas station"
    echo "  logs:  View the latest IOTA network logs (follow mode)"
    echo "  gaslogs: View the latest gas station logs (follow mode)"
fi
