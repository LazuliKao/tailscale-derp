# tailscale-derp

Tailscale DERP and STUN server with optional client verification through the
official Tailscale API.

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
```

Store the corresponding API key separately in
`/etc/config/tailscale-derp-secrets`:

```uci
config secret 'primary'
	option api_key 'tskey-api-...'
```

On non-Windows systems the secrets file must not be readable by group or
others (for example, `chmod 600 /etc/config/tailscale-derp-secrets`). The API
key is used for device synchronization and for the loopback-only management
endpoints below. Grant it only the Tailscale API permissions required by the
operations you intend to use.

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
