## HTTP/3 Example

This example shows how to serve HTTP/3 (QUIC) next to an HTTPS listener.

### Running the example

```bash
cargo run -- -f examples/traffic-http3/config.yaml
```

Beyond the [TLS](../mcp-tls) configuration, the `http3` frontend policy turns on HTTP/3 for every HTTPS listener of the bind:

```yaml
frontendPolicies:
  http:
    http3:
      altSvcMaxAge: 1h
```

agentgateway then binds UDP port 3000, the same port number as the TCP listener, terminates QUIC with the listener's certificate (selected by SNI, as for TCP), and serves the requests through the same routes and policies as HTTP/1.1 and HTTP/2.
HTTP/3 is disabled unless the policy is set, and no UDP socket is opened.

Clients usually discover HTTP/3 through the `Alt-Svc` header that agentgateway adds to responses on the TCP listener:

```bash
$ curl -sk -o /dev/null -D - https://localhost:3000
HTTP/1.1 200 OK
alt-svc: h3=":3000"; ma=3600
...
```

With a `curl` built with HTTP/3 support, the request can be sent over QUIC directly:

```bash
$ curl -k --http3-only https://localhost:3000
hello
```

Note the `-k` to disable TLS verification, as the example certificate is self-signed.

HTTP/3 is only served for HTTPS listeners that do not verify client certificates, and it requires TLS 1.3.
The `idleTimeout` and `maxConcurrentStreams` fields tune the QUIC connections.
