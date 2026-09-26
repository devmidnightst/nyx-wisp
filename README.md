# nyx

Wisp is a protocol for multiplexing TCP and UDP sockets over a single websocket connection. This is a clean-room Rust implementation of [Wisp v2](https://github.com/MercuryWorkshop/wisp-protocol/blob/v2/protocol.md), written directly against the spec rather than ported from any existing implementation.

## layout

- `wisp-core` - the protocol itself: frame encode/decode, close reasons, extensions, flow control, handshake and stream state machines. No I/O, usable as a library on its own.
- `wisp-server` - `nyx-server` binary. Accepts websocket connections and proxies streams to real TCP/UDP sockets.
- `wisp-client` - `nyx-client` binary. Connects to a server and opens a single stream for testing.

## build

    cargo build --release

Binaries end up at `target/release/nyx-server` and `target/release/nyx-client`.

## test

    cargo test

## running it

Start a server:

    nyx-server --bind 127.0.0.1:9000

Point a client at it and open a TCP stream:

    nyx-client ws://127.0.0.1:9000/ --tcp example.com:80

Whatever you type goes into the stream, whatever comes back gets printed to stdout. Use `--udp host:port` instead of `--tcp` for a UDP stream.

Server flags: `--buffer-size <n>`, `--username`/`--password` (both required together), `--password-optional`, `--motd <text>`, `--key-auth-pubkey <hex>` (repeatable, ed25519), `--key-auth-optional`.

Client flags: `--username`/`--password` and `--key-auth-privkey <hex>`, sent only if the server asked for them.

## protocol coverage

Full v2 handshake (INFO/CONTINUE negotiation, not v1 fallback), password auth extension, ed25519 key auth extension, MOTD extension, and the CONTINUE-based flow control from the spec, not a simplified stand-in for it.

## license

MIT
