# Wiring `plaude` into bifrost (VLLM/OpenWebUI flow)

This repo ships an MCP server (`scripts/mcp_plaude_server.py`) that exposes the
local `plaude` CLI as two callable tools:

- `plaude_list` — list recordings on the device (no download)
- `plaude_sync` — connect, download new recordings, decode to WAV

Bifrost (the MaximHQ LLM gateway at `https://bifrost.siliconspirit.net`) can
register MCP servers and expose their tools to any model it serves (OpenWebUI
assistant, CLI, etc.) via `mcp.client_configs`.

## 1. Run the server

HTTP transport (for bifrost — must be reachable from the host running bifrost):

```sh
cd /Users/terafin/Projects/plaude/openplaudit
venv/bin/python scripts/mcp_plaude_server.py \
  --transport http --host 0.0.0.0 --port 8844
```

stdio transport (for a local MCP client / hermes):

```sh
venv/bin/python scripts/mcp_plaude_server.py --transport stdio
```

The `--plaude` flag overrides the CLI path (default
`/Users/terafin/Projects/plaude/openplaudit/venv/bin/plaude`).

## 2. Register in bifrost

In bifrost's config (the `mcp.client_configs` array — see
`examples/configs/withpostgresmcpclientsinconfig/config.json`), add:

```json
"mcp": {
  "client_configs": [
    {
      "name": "plaude",
      "connection_type": "http",
      "client_id": "plaude-mcp",
      "connection_string": "http://<host>:8844/mcp"
    }
  ]
}
```

The `connection_string` must be reachable from bifrost. If bifrost runs in
docker on the same host, use the host's LAN IP or a docker-network alias.

> This change touches the shared bifrost service — it needs the owner's OK
> before applying (see home-cluster rules: shared-infra runtime changes are
> gated).

## 3. Use it

Once registered, any model routed through bifrost can call `plaude_sync` with
the tool. The device must be awake (tap the Record button) and idle (not
recording) for the sync to succeed.

## Requirements

- `mcp` (Python SDK) installed in the openplaudit venv:
  `venv/bin/pip install mcp`
- The `plaude` CLI reachable at the `--plaude` path.
- Device configured (see `~/.config/openplaudit/config.toml`) and awake.
