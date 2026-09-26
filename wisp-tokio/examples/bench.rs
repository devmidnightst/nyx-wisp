//! Throughput and latency benchmark: a wisp server and client in one process, proxying to a local
//! TCP echo server. Run with `cargo run --release -p wisp-tokio --example bench`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use wisp_tokio::client::{self, ClientConfig, ClientMux};
use wisp_tokio::server::{self, ServerConfig};

async fn start_server(config: ServerConfig) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = Arc::new(config);
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let _ = socket.set_nodelay(true);
            let config = config.clone();
            tokio::spawn(async move {
                let _ = server::accept(socket, config).await;
            });
        }
    });
    addr
}

async fn echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let _ = socket.set_nodelay(true);
            tokio::spawn(async move {
                let (mut read, mut write) = socket.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    port
}

async fn connect(addr: SocketAddr) -> ClientMux {
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    tcp.set_nodelay(true).unwrap();
    let request = client::request(&format!("ws://{addr}/")).unwrap();
    let (ws, _) = tokio_tungstenite::client_async_with_config(request, tcp, Some(wisp_tokio::websocket_config()))
        .await
        .unwrap();
    ClientMux::new(ws, ClientConfig::default()).await.unwrap()
}

/// pushes `total` bytes through one stream and reads them back, returns bytes per second
async fn echo_throughput(mux: ClientMux, port: u16, total: usize) -> f64 {
    let stream = mux.open_tcp("127.0.0.1", port).await.unwrap();
    let (mut read, mut write) = tokio::io::split(stream);
    let start = Instant::now();
    let writer = tokio::spawn(async move {
        let chunk = vec![0x5au8; 64 * 1024];
        let mut sent = 0;
        while sent < total {
            let len = chunk.len().min(total - sent);
            write.write_all(&chunk[..len]).await.unwrap();
            sent += len;
        }
        write
    });
    let mut buf = vec![0u8; 256 * 1024];
    let mut received = 0;
    while received < total {
        let n = read.read(&mut buf).await.unwrap();
        assert!(n > 0, "stream ended early");
        received += n;
    }
    let elapsed = start.elapsed();
    drop(writer.await.unwrap());
    total as f64 / elapsed.as_secs_f64()
}

fn mib(bytes_per_sec: f64) -> String {
    format!("{:>8.1} MiB/s", bytes_per_sec / (1024.0 * 1024.0))
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    sorted[((sorted.len() as f64 - 1.0) * p).round() as usize]
}

#[tokio::main]
async fn main() {
    let scale: usize = std::env::var("BENCH_SCALE").ok().and_then(|v| v.parse().ok()).unwrap_or(1);
    let addr = start_server(ServerConfig::default()).await;
    let port = echo_server().await;

    // warm up
    echo_throughput(connect(addr).await, port, 8 << 20).await;

    let total = (256 * scale) << 20;
    let rate = echo_throughput(connect(addr).await, port, total).await;
    println!("single stream echo       {}", mib(rate));

    let streams = 16;
    let mux = connect(addr).await;
    let per_stream = (32 * scale) << 20;
    let start = Instant::now();
    let mut tasks = Vec::new();
    for _ in 0..streams {
        tasks.push(tokio::spawn(echo_throughput(mux.clone(), port, per_stream)));
    }
    let all = async {
        for task in tasks {
            task.await.unwrap();
        }
    };
    if tokio::time::timeout(Duration::from_secs(60), all).await.is_ok() {
        let aggregate = (streams * per_stream) as f64 / start.elapsed().as_secs_f64();
        println!("{streams} streams echo, total  {}", mib(aggregate));
    } else {
        println!("{streams} streams echo, total  froze (no progress after 60s)");
    }

    let mux = connect(addr).await;
    let mut stream = mux.open_tcp("127.0.0.1", port).await.unwrap();
    let rounds = 20_000 * scale;
    let mut buf = [0u8; 64];
    let mut latencies = Vec::with_capacity(rounds);
    for _ in 0..rounds {
        let start = Instant::now();
        stream.write_all(&[7u8; 64]).await.unwrap();
        stream.read_exact(&mut buf).await.unwrap();
        latencies.push(start.elapsed());
    }
    latencies.sort();
    println!(
        "64 byte round trip       p50 {:>6.1}us  p99 {:>6.1}us",
        percentile(&latencies, 0.5).as_secs_f64() * 1e6,
        percentile(&latencies, 0.99).as_secs_f64() * 1e6
    );
    drop(stream);

    let opens = 2_000 * scale;
    let start = Instant::now();
    for _ in 0..opens {
        let mut stream = mux.open_tcp("127.0.0.1", port).await.unwrap();
        stream.write_all(b"x").await.unwrap();
        stream.read_exact(&mut buf[..1]).await.unwrap();
    }
    println!(
        "open + 1 byte echo       {:>8.0} streams/s",
        opens as f64 / start.elapsed().as_secs_f64()
    );
}
