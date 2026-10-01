# tailscale-derp

Tailscale DERP and STUN server with optional client verification through the
official Tailscale API.

## Configuration formats

Configuration-file support is selected at build time. A binary without a
configuration build tag accepts command-line flags only. Enable one or more
formats with Go build tags:

```sh
go build -tags uciconfig ./cmd/tailscale-derp
go build -tags jsonconfig ./cmd/tailscale-derp
go build -tags yamlconfig ./cmd/tailscale-derp
go build -tags "uciconfig jsonconfig yamlconfig" ./cmd/tailscale-derp
```

The `--config` file name determines its format: `.json` selects JSON, `.yaml`
or `.yml` selects YAML, and all other names select UCI. When `uciconfig` is
enabled, `/etc/config/tailscale-derp` is the default configuration path.
Selecting a format not included in the binary produces an error naming the
required build tag. Command-line flags always override settings loaded from a
file.

JSON and YAML use the same nested configuration structure. For example:

```yaml
global:
  enabled: true
  listen: ":3478"
  stun: true

tls:
  mode: self_signed

verify_api:
  - name: primary
    tailnet: "-"
    auth_type: api_key
    api_key: tskey-api-...
```

Generate the committed JSON Schema with:

```sh
go generate ./...
```

The output is [`schema/tailscale-derp.schema.json`](schema/tailscale-derp.schema.json).
It can also validate equivalent YAML in editors that support JSON Schema.

## Tailscale API configuration

Define each tailnet in the main UCI configuration (normally
`/etc/config/tailscale-derp`):

```uci
config verify 'verify'
	option enabled '1'
	option api_enabled '1'

config verify_api 'primary'
	option label 'Primary tailnet'
	option tailnet '-'
	option auth_type 'api_key'
	option api_key 'tskey-api-...'
```

For OAuth client credentials, store `oauth_client_id` and
`oauth_client_secret` in the same `verify_api` section instead of `api_key`.
Credentials are loaded into memory at startup and are never included in
status or device responses. The API key is used for device synchronization and
for the loopback-only management endpoints below. Grant it only the Tailscale
API permissions required by the operations you intend to use.

## Tailnet management API

The management API is served by the existing ops listener, which must bind to
a loopback address (default `127.0.0.1:9911`). It has no additional
authentication, so do not expose it through a reverse proxy or public network.

All examples below use:

```sh
BASE=http://127.0.0.1:9911
```

List configured tailnets. API keys are never returned:

```sh
curl "$BASE/tailnets"
```

Set a device IPv4 address. `deviceID` is the Tailscale device node ID returned
by `/devices`:

```sh
curl -X PUT "$BASE/tailnets/primary/devices/nodeid:123/ip" \
  -H 'Content-Type: application/json' \
  --data '{"ipv4":"100.64.0.10"}'
```

Read the tailnet ACL as its original HuJSON and retain the returned ETag:

```sh
curl "$BASE/tailnets/primary/acl"
```

The response has this shape:

```json
{"hujson":"// comments are preserved\n{...}\n","etag":"version"}
```

Validate HuJSON before writing it:

```sh
curl -X POST "$BASE/tailnets/primary/acl/validate" \
  -H 'Content-Type: application/json' \
  --data '{"hujson":"{\"acls\": []}"}'
```

Write the ACL with the ETag obtained from `GET /acl`:

```sh
curl -X PUT "$BASE/tailnets/primary/acl" \
  -H 'Content-Type: application/json' \
  --data '{"hujson":"// retained comment\n{\"acls\": []}\n","etag":"version"}'
```

Writes are validated first. A `409 Conflict` means the policy changed after it
was read; fetch the latest document and ETag, reapply the intended edit, then
try again.
