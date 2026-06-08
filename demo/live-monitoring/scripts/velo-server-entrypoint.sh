#!/bin/bash
# velo-server entrypoint.
#
# 1. First boot: generate server.config.yaml, client.config.yaml,
#    api.config.yaml into /config (shared volume; victim reads client.config
#    from here too).
# 2. Override the demo-friendly tunings: bind 0.0.0.0, drop client batch
#    wait to 10s so events stream in near-realtime.
# 3. Start the frontend.

set -euo pipefail

CONFIG=/config/server.config.yaml
CLIENT=/config/client.config.yaml
API=/config/api.config.yaml

generate_configs() {
    echo "[velo-server] No config found at ${CONFIG} — generating fresh demo configs"

    # `config generate` with --merge applies the JSON patch onto sensible
    # defaults. Bind everything to 0.0.0.0 so other containers on the same
    # bridge network can reach the frontend and API. The client batch
    # tunable is overridden in the client config (see post-merge below).
    velociraptor config generate \
        --merge '{
            "Client": {
                "server_urls": ["https://velo-server:8000/"],
                "use_self_signed_ssl": true,
                "event_min_batch_wait": 10
            },
            "API": {
                "bind_address": "0.0.0.0",
                "bind_port": 8001,
                "hostname": "localhost"
            },
            "GUI": {
                "bind_address": "0.0.0.0",
                "bind_port": 8889,
                "public_url": "https://velo-server:8889/app/index.html"
            },
            "Frontend": {
                "bind_address": "0.0.0.0",
                "bind_port": 8000,
                "public_url": "https://velo-server:8000/"
            },
            "Datastore": {
                "implementation": "FileBaseDataStore",
                "location": "/data",
                "filestore_directory": "/data/filestore"
            },
            "Logging": {
                "output_directory": "/data/logs",
                "separate_logs_per_component": true
            }
        }' > "${CONFIG}"

    # Extract the client + API configs from the merged server config. These
    # are derived configs that share the server's CA — they must come from
    # the same generation run.
    velociraptor --config "${CONFIG}" config client > "${CLIENT}"
    # api_client takes the output path as a positional argument. The
    # endpoint the client will dial is taken from API.hostname in the
    # server config (set above to "localhost" so TRUDI on the SIFT host
    # can reach it through the forwarded port).
    velociraptor --config "${CONFIG}" config api_client \
        --name trudi-mcp --role administrator \
        "${API}"

    chmod 644 "${CONFIG}" "${CLIENT}" "${API}"
    echo "[velo-server] Configs generated:"
    ls -la /config
}

mkdir -p /config /data
if [[ ! -f "${CONFIG}" ]]; then
    generate_configs
else
    echo "[velo-server] Reusing existing config at ${CONFIG}"
fi

echo "[velo-server] Starting frontend …"
exec velociraptor --config "${CONFIG}" frontend -v
