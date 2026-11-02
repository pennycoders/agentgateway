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
One QUIC endpoint serves every HTTPS listener of the bind with the TLS settings of the frontend `tls` policy, so listeners whose own TLS versions, cipher suites or key exchange groups differ are not served over HTTP/3.
It is not served on binds that use the PROXY protocol, a CONNECT tunnel, or another tunnel protocol, since these change the TCP stream before HTTP and have no QUIC equivalent.
The `idleTimeout`, `maxConcurrentStreams`, `requestHeaderTimeout` and `keepAliveInterval` fields tune the QUIC connections; `keepAliveInterval` sends QUIC PING frames on idle connections for clients behind NATs that drop UDP mappings after a short time, and must be shorter than `idleTimeout`; the HTTP/2 flow-control windows (`http2WindowSize`, `http2ConnectionWindowSize`) do not apply to QUIC, whose flow-control windows are sized for 100 Mbit/s at a 100 ms round trip per stream.

When HTTP/3 is disabled again, responses carry `Alt-Svc: clear` for the advertised `altSvcMaxAge`, so clients forget the cached advertisement.

The UDP port must be reachable by clients.
The gateway asks for 4 MiB UDP socket buffers so bursts of QUIC packets are not dropped; Linux grants at most `net.core.rmem_max` and `net.core.wmem_max`, so raise these sysctls on the host for the full size.
On Kubernetes, the controller adds a UDP port to the Service of the Gateways it deploys for every HTTPS listener on which an `AgentgatewayPolicy` enables HTTP/3.
A `LoadBalancer` Service then has both TCP and UDP ports, which some load balancer implementations do not support; in that case, expose the UDP port with a separate Service.
When clients reach the gateway on a different port, for example through NAT or a load balancer that remaps ports, set `altSvcPort` to the port they should use.
