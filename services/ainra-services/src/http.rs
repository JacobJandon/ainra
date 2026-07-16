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
    Ok(raw.splitn(2, "\r\n\r\n").nth(1).unwrap_or("").to_string())
}
pub fn http_get(addr: &str, path: &str) -> std::io::Result<String> {
    http_request(addr, "GET", path, None)
}
pub fn http_post(addr: &str, path: &str, body: &str) -> std::io::Result<String> {
    http_request(addr, "POST", path, Some(body))
}

/// Serve until the process is killed. `handler(req) -> (status_code, json_body)`.
pub fn serve<F>(addr: &str, handler: F) -> std::io::Result<()>
where
    F: Fn(&Request) -> (u16, String) + Sync,
{
    let listener = TcpListener::bind(addr)?;
    eprintln!("listening on http://{addr}");
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(_) => continue,
        };
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).is_err() || request_line.is_empty() {
            continue;
        }
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or("").to_string();
        let path = parts.next().unwrap_or("/").to_string();
        // headers → content-length
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                break;
            }
            let t = line.trim_end();
            if t.is_empty() {
                break;
            }
            if let Some(v) = t.to_ascii_lowercase().strip_prefix("content-length:") {
                content_length = v.trim().parse().unwrap_or(0);
            }
        }
        // Cap the body so an attacker-controlled `Content-Length` cannot force an unbounded allocation (review #5).
        // 1 MiB is far above any real request here; an oversized body is rejected, not eagerly allocated.
        const MAX_BODY: usize = 1 << 20;
        if content_length > MAX_BODY {
            let resp = "HTTP/1.1 400 Bad Request\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(resp.as_bytes());
            continue;
        }
        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            let _ = reader.read_exact(&mut body);
        }
        let req = Request {
            method,
            path,
            body: String::from_utf8_lossy(&body).into_owned(),
        };
        // A browser preflights cross-origin POSTs; answer OPTIONS directly so the LOCAL explorer can talk to the
        // daemon. These daemons are reference/dev tools: they bind 127.0.0.1, carry no auth, and use permissive
        // CORS so the local explorer's live-verify/revoke works. That is a deliberate dev-only posture (any local
        // page can drive them) — NOT the hardened deployment (auth + origin allow-list + TLS are M4–M8). See STATUS.
        if req.method == "OPTIONS" {
            let resp = "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
            continue;
        }
        let (code, json) = handler(&req);
        let reason = match code {
            200 => "OK",
            400 => "Bad Request",
            404 => "Not Found",
            _ => "Error",
        };
        let resp = format!(
            "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{json}",
            json.len()
        );
        let _ = stream.write_all(resp.as_bytes());
        let _ = stream.flush();
    }
    Ok(())
}
