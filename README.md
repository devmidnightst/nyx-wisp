# nyx

Wisp is a protocol for multiplexing TCP and UDP sockets over a single websocket connection. This is a clean-room Rust implementation of [Wisp v2](https://github.com/MercuryWorkshop/wisp-protocol/blob/v2/protocol.md), written directly against the spec rather than ported from any existing implementation. It interoperates with MercuryWorkshop's [wisp-js](https://github.com/MercuryWorkshop/wisp-js) client and server.

## layout

- `wisp-core` - the protocol itself: frame encode/decode, close reasons, extensions, flow control, handshake and stream state machines. No I/O, usable as a library on its own.
- `wisp-tokio` - async client and server multiplexers on tokio and tokio-tungstenite. The server side works over any `AsyncRead + AsyncWrite` socket, so plain TCP and TLS both work. The client side hands out `WispStream`s that implement `AsyncRead`/`AsyncWrite` like a normal socket.
- `wisp-server` - `nyx-server` binary. Accepts websocket connections (optionally over TLS) and proxies streams to real TCP/UDP sockets.
- `wisp-client` - `nyx-client` binary. Connects to a server (`ws://` or `wss://`) and pipes one stream to stdin/stdout.

## build

    cargo build --release

Binaries end up at `target/release/nyx-server` and `target/release/nyx-client`.

## test

    cargo test

CI runs build, clippy (warnings denied) and the full test suite on every push to main and every pull request.

## benchmark

    cargo run --release -p wisp-tokio --example bench

Runs a server and a client in one process against a local TCP echo server, and prints throughput and latency. Set `BENCH_SCALE` to multiply the amount of data. On a 4 core VM:

| | |
|---|---|
| single stream echo | ~530 MiB/s |
| 16 streams echo, total | ~1000 MiB/s |
| 64 byte round trip | ~61 us p50, ~125 us p99 |
| open a stream + echo 1 byte | ~5300 streams/s |

Echo throughput counts each byte once, even though it crosses both the websocket and the upstream socket in each direction.

## running it

Start a server:

    nyx-server --bind 127.0.0.1:9000

Point a client at it and open a TCP stream:

    nyx-client ws://127.0.0.1:9000/ --tcp example.com:80

Whatever you type goes into the stream, whatever comes back gets printed to stdout. Use `--udp host:port` instead of `--tcp` for a UDP stream. Wisp has no half-close, so the stream closes when stdin ends.

To serve `wss://` directly, give the server a PEM certificate chain and key:

    nyx-server --bind 0.0.0.0:443 --tls-cert fullchain.pem --tls-key privkey.pem

Behind a reverse proxy that terminates TLS (caddy, nginx), run it without the TLS flags.

### server flags

| flag | default | |
|---|---|---|
| `--bind <addr>` | `127.0.0.1:9000` | address to listen on |
| `--buffer-size <n>` | `128` | packets each TCP stream may buffer (the CONTINUE window), at least 1 |
| `--username`, `--password` | | enable password auth (both required together) |
| `--password-optional` | | let clients skip password auth |
| `--key-auth-pubkey <hex>` | | allow an ed25519 public key, repeatable |
| `--key-auth-optional` | | let clients skip key auth |
| `--motd <text>` | | message of the day sent to v2 clients |
| `--no-udp` | | refuse UDP streams |
| `--no-stream-confirmation` | | stop offering the stream open confirmation extension |
| `--connect-timeout <secs>` | `10` | upstream TCP connect timeout |
| `--handshake-timeout <secs>` | `10` | how long a client may take to send its INFO |
| `--tls-cert <pem>`, `--tls-key <pem>` | | serve `wss://` |

When both auth methods are enabled, either one is enough.

### client flags

`--username`/`--password` and `--key-auth-privkey <hex>`, sent only if the server asks for them. `--ca-cert <pem>` trusts an extra CA for `wss://`, on top of the built in web roots, which is handy for self-signed certificates.

## using the library

```rust
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wisp_tokio::client::{self, ClientConfig, ClientMux};

let request = client::request("ws://127.0.0.1:9000/")?;
let config = Some(wisp_tokio::websocket_config());
let (ws, _) = tokio_tungstenite::connect_async_with_config(request, config, false).await?;
let mux = ClientMux::new(ws, ClientConfig::default()).await?;
let mut stream = mux.open_tcp("example.com", 80).await?;
stream.write_all(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n").await?;
let mut response = Vec::new();
stream.read_to_end(&mut response).await?;
```

`websocket_config()` is optional but recommended: it sizes tungstenite's read buffer for wisp's mostly small frames, which lowers latency.

Serving is one call per accepted socket:

```rust
use std::sync::Arc;
use wisp_tokio::server::{self, ServerConfig};

let config = Arc::new(ServerConfig::default());
let (socket, _) = listener.accept().await?;
tokio::spawn(server::accept(socket, config));
```

## protocol coverage

- v2 handshake (INFO/CONTINUE negotiation), with v1 served to clients that don't send `Sec-WebSocket-Protocol`
- CONTINUE based flow control, with real backpressure on both the server and the client
- extensions: UDP (0x01), password auth (0x02), ed25519 key auth (0x03), MOTD (0x04) and stream open confirmation (0x05)
- every close reason in the spec, mapped from the real socket errors

## license

MIT
