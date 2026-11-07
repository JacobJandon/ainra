// SPDX-License-Identifier: Apache-2.0 OR MIT
//! A minimal, dependency-free blocking HTTP/1.1 server (std::net only) shared by the service daemons. Local by
//! default (bind 127.0.0.1), zero telemetry. This is glue — no security decision is made here; handlers return
//! JSON strings and the core does the deciding.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};

pub struct Request {
    pub method: String,
    pub path: String,
    pub body: String,
    /// Request headers, keys lowercased (e.g. `authorization`). Populated by [`serve`]; empty for client calls.
    pub headers: std::collections::BTreeMap<String, String>,
    /// Peer IP (no port), for coarse per-source rate limiting in a staging deployment. `""` if unavailable.
    pub peer: String,
}

/// A minimal blocking HTTP/1.1 CLIENT (std::net only) so the service daemons can talk to each other — e.g. a relying
/// party fetching cosignatures from a NETWORKED witness quorum (D-021 transport). Returns the response body. This is
/// dumb transport: it carries no trust; the caller decides security by verifying the signatures it fetched. TLS is a
/// reverse-proxy/deployment concern, not built in here (matching the daemons' local-by-default posture).
pub fn http_request(
    addr: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(addr)?;
    let b = body.unwrap_or("");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
        b.len()
    );
    stream.write_all(req.as_bytes())?;
    stream.flush()?;
    let mut raw = String::new();
    stream.read_to_string(&mut raw)?;
    Ok(raw
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_string())
        .unwrap_or_default())
}
pub fn http_get(addr: &str, path: &str) -> std::io::Result<String> {
    http_request(addr, "GET", path, None)
}
pub fn http_post(addr: &str, path: &str, body: &str) -> std::io::Result<String> {
    http_request(addr, "POST", path, Some(body))
}

/// How long a connection may stall on a read or a write before it is dropped.
const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// The longest request line or header line accepted, and the most header lines.
const MAX_LINE: u64 = 8 * 1024;
const MAX_HEADERS: usize = 100;
/// The most connections served at once; one more is closed at once rather than queued behind the others.
const MAX_CONNECTIONS: usize = 64;

/// Serve until the process is killed. `handler(req) -> (status_code, json_body)`.
///
/// Each connection is served on its own thread, at most [`MAX_CONNECTIONS`] at once, with read and write timeouts and
/// bounded line lengths. The server used to read connections one at a time with no timeout: a single client that
/// opened a socket and sent nothing stopped every request to the registrar (found by the 2026-11-07 review).
pub fn serve<F>(addr: &str, handler: F) -> std::io::Result<()>
where
    F: Fn(&Request) -> (u16, String) + Sync,
{
    use std::sync::atomic::{AtomicUsize, Ordering};
    let listener = TcpListener::bind(addr)?;
    eprintln!("listening on http://{addr}");
    let live = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            if live.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                live.fetch_sub(1, Ordering::SeqCst);
                drop(stream);
                continue;
            }
            let (handler, live) = (&handler, &live);
            scope.spawn(move || {
                let _ = serve_one(stream, handler);
                live.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    Ok(())
}

/// Read one line of at most [`MAX_LINE`] bytes. `None` on a read error, a timeout, or a line that does not end in time.
fn bounded_line(reader: &mut BufReader<TcpStream>) -> Option<String> {
    let mut line = String::new();
    let n = reader.by_ref().take(MAX_LINE).read_line(&mut line).ok()?;
    if n as u64 >= MAX_LINE && !line.ends_with('\n') {
        return None;
    }
    Some(line)
}

fn serve_one<F>(mut stream: TcpStream, handler: &F) -> std::io::Result<()>
where
    F: Fn(&Request) -> (u16, String) + Sync,
{
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let Some(request_line) = bounded_line(&mut reader) else {
        return Ok(());
    };
    if request_line.is_empty() {
        return Ok(());
    }
    let peer = stream
        .peer_addr()
        .map(|a| a.ip().to_string())
        .unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("/").to_string();
    // headers → content-length + captured map (lowercased keys)
    let mut content_length = 0usize;
    let mut headers = std::collections::BTreeMap::new();
    for _ in 0..=MAX_HEADERS {
        let Some(line) = bounded_line(&mut reader) else {
            return Ok(());
        };
        let t = line.trim_end();
        if t.is_empty() {
            break;
        }
        if headers.len() >= MAX_HEADERS {
            return Ok(());
        }
        if let Some((k, v)) = t.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            if key == "content-length" {
                content_length = v.trim().parse().unwrap_or(0);
            }
            headers.insert(key, v.trim().to_string());
        }
    }
    // Cap the body so an attacker-controlled `Content-Length` cannot force an unbounded allocation (review #5).
    // 1 MiB is far above any real request here; an oversized body is rejected, not eagerly allocated.
    const MAX_BODY: usize = 1 << 20;
    if content_length > MAX_BODY {
        let resp = "HTTP/1.1 400 Bad Request\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(resp.as_bytes());
        return Ok(());
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 && reader.read_exact(&mut body).is_err() {
        return Ok(());
    }
    let req = Request {
        method,
        path,
        body: String::from_utf8_lossy(&body).into_owned(),
        headers,
        peer,
    };
    // A browser preflights cross-origin POSTs; answer OPTIONS directly so the LOCAL explorer can talk to the
    // daemon. These daemons are reference/dev tools: they bind 127.0.0.1, carry no auth, and use permissive
    // CORS so the local explorer's live-verify/revoke works. That is a deliberate dev-only posture (any local
    // page can drive them) — NOT the hardened deployment (auth + origin allow-list + TLS are M4–M8). See STATUS.
    if req.method == "OPTIONS" {
        let resp = "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        let _ = stream.write_all(resp.as_bytes());
        let _ = stream.flush();
        return Ok(());
    }
    let (code, json) = handler(&req);
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Error",
    };
    // A JSON body never starts with '<'; an HTML body (the registrar console) does. This lets a handler serve
    // the console as text/html without changing the (u16, String) handler signature every route shares.
    let ctype = if json.trim_start().starts_with('<') {
        "text/html; charset=utf-8"
    } else if json.starts_with("eyJ") && json.matches('.').count() == 2 {
        // A compact JWS (the Token Status List mirror): base64url of '{"…', never JSON, never HTML.
        "application/statuslist+jwt"
    } else {
        "application/json"
    };
    let resp = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {ctype}\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json}",
        json.len()
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
    Ok(())
}
