use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const STREAM_MAGIC: &[u8; 4] = b"HRS1";
const STREAM_OP_OPEN: u8 = 1;
const STREAM_OP_DATA: u8 = 2;
const STREAM_OP_CLOSE: u8 = 3;
const STREAM_DATA_OFFSET: usize = 64;

struct SenderConfig {
    policy_info: String,
    sender_bin: String,
    rounds: String,
    payload_len: usize,
    host_offset: usize,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("hornet_proxy error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let bind = env::var("HORNET_PROXY_BIND").unwrap_or_else(|_| "127.0.0.1:18080".to_string());
    let listener = TcpListener::bind(&bind).map_err(|e| format!("bind {bind}: {e}"))?;
    println!("hornet_proxy listening on {bind}");
    loop {
        let (mut stream, peer) = listener.accept().map_err(|e| format!("accept: {e}"))?;
        if let Err(err) = handle_client(&mut stream) {
            eprintln!("proxy client {peer}: {err}");
            let _ = send_http_error(&mut stream, 502, "Bad Gateway", &err);
        }
    }
}

fn handle_client(stream: &mut TcpStream) -> Result<(), String> {
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .ok();
    stream
        .set_write_timeout(Some(std::time::Duration::from_secs(5)))
        .ok();

    let req = read_http_request(stream)?;
    let (method, target_host, target_port) = parse_target(&req)?;
    let cfg = SenderConfig {
        policy_info: env::var("HORNET_POLICY_INFO")
            .unwrap_or_else(|_| "config/localnet/policy-info.json".to_string()),
        sender_bin: env::var("HORNET_DATA_SENDER_BIN")
            .unwrap_or_else(|_| "target/debug/hornet_data_sender".into()),
        rounds: env::var("HORNET_PROXY_ZKBOO_ROUNDS").unwrap_or_else(|_| "8".to_string()),
        payload_len: env::var("HORNET_PROXY_PAYLOAD_LEN")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(96),
        host_offset: env::var("HORNET_PROXY_HOST_OFFSET")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(16),
    };
    let target = format!("{target_host}:{target_port}");

    if method.eq_ignore_ascii_case("CONNECT") {
        handle_connect_tunnel(stream, &cfg, &target, &target_host)
    } else {
        let outbound = normalize_http_request_for_policy(&req, &target_host, &cfg)?;
        eprintln!(
            "[proxy] forward HTTP {}:{} (in={} out={})",
            target_host,
            target_port,
            req.len(),
            outbound.len()
        );
        let response = run_sender(&cfg, &target, &outbound)?;
        eprintln!("[proxy] got response bytes={}", response.len());
        stream
            .write_all(&response)
            .map_err(|e| format!("write response: {e}"))
    }
}

fn handle_connect_tunnel(
    stream: &mut TcpStream,
    cfg: &SenderConfig,
    target: &str,
    host: &str,
) -> Result<(), String> {
    let session_id = fresh_session_id()?;

    let open_payload = build_stream_payload(
        cfg.payload_len,
        cfg.host_offset,
        host,
        STREAM_OP_OPEN,
        session_id,
        &[],
    )?;
    let _ = run_sender(cfg, target, &open_payload)?;
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .map_err(|e| format!("write connect ok: {e}"))?;

    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .ok();
    loop {
        let max_chunk = cfg.payload_len.saturating_sub(STREAM_DATA_OFFSET);
        let mut chunk = vec![0u8; max_chunk.max(1)];
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                let payload = build_stream_payload(
                    cfg.payload_len,
                    cfg.host_offset,
                    host,
                    STREAM_OP_DATA,
                    session_id,
                    &chunk[..n],
                )?;
                let response = run_sender(cfg, target, &payload)?;
                if !response.is_empty() {
                    stream
                        .write_all(&response)
                        .map_err(|e| format!("write tunnel response: {e}"))?;
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                let payload = build_stream_payload(
                    cfg.payload_len,
                    cfg.host_offset,
                    host,
                    STREAM_OP_DATA,
                    session_id,
                    &[],
                )?;
                let response = run_sender(cfg, target, &payload)?;
                if !response.is_empty() {
                    stream
                        .write_all(&response)
                        .map_err(|err| format!("write tunnel poll response: {err}"))?;
                }
            }
            Err(e) => return Err(format!("read tunnel client: {e}")),
        }
    }

    let close_payload = build_stream_payload(
        cfg.payload_len,
        cfg.host_offset,
        host,
        STREAM_OP_CLOSE,
        session_id,
        &[],
    )?;
    let _ = run_sender(cfg, target, &close_payload)?;
    Ok(())
}

fn run_sender(cfg: &SenderConfig, target: &str, request: &[u8]) -> Result<Vec<u8>, String> {
    let req_path = write_temp_request(request)?;
    let rsp_path = temp_path("hornet-proxy-rsp")?;
    let output = Command::new(&cfg.sender_bin)
        .arg(&cfg.policy_info)
        .arg(target)
        .arg("00")
        .env("HORNET_REQUEST_PATH", &req_path)
        .env("HORNET_RESPONSE_OUTPUT_PATH", &rsp_path)
        .env("HORNET_ZKBOO_ROUNDS", &cfg.rounds)
        .output()
        .map_err(|e| format!("spawn hornet_data_sender: {e}"))?;
    let _ = fs::remove_file(&req_path);

    if !output.status.success() {
        let _ = fs::remove_file(&rsp_path);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(format!(
            "hornet_data_sender failed (status={}): {} {}",
            output.status,
            stderr.trim(),
            stdout.trim()
        ));
    }

    let bytes = fs::read(&rsp_path).map_err(|e| format!("read sender response output: {e}"))?;
    eprintln!(
        "[proxy] sender ok target={} req_bytes={} rsp_bytes={}",
        target,
        request.len(),
        bytes.len()
    );
    let _ = fs::remove_file(&rsp_path);
    Ok(bytes)
}

fn build_stream_payload(
    payload_len: usize,
    host_offset: usize,
    host: &str,
    op: u8,
    session_id: u64,
    data: &[u8],
) -> Result<Vec<u8>, String> {
    if payload_len < STREAM_DATA_OFFSET {
        return Err(format!("payload len must be >= {}", STREAM_DATA_OFFSET));
    }
    let host_header = {
        let mut v = Vec::with_capacity(6 + host.len() + 2);
        v.extend_from_slice(b"Host: ");
        v.extend_from_slice(host.as_bytes());
        v.extend_from_slice(b"\r\n");
        v
    };
    if host_offset + host_header.len() > payload_len {
        return Err("host header does not fit payload policy window".into());
    }
    if data.len() > u16::MAX as usize {
        return Err("data too large".into());
    }
    if STREAM_DATA_OFFSET + data.len() > payload_len {
        return Err("data does not fit payload frame".into());
    }

    let mut out = vec![0u8; payload_len];
    out[..4].copy_from_slice(STREAM_MAGIC);
    out[4] = op;
    out[6..8].copy_from_slice(&(data.len() as u16).to_be_bytes());
    out[8..16].copy_from_slice(&session_id.to_be_bytes());
    out[STREAM_DATA_OFFSET..STREAM_DATA_OFFSET + data.len()].copy_from_slice(data);
    out[host_offset..host_offset + host_header.len()].copy_from_slice(&host_header);
    Ok(out)
}

fn fresh_session_id() -> Result<u64, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "clock error")?
        .as_nanos();
    Ok((now & 0xFFFF_FFFF_FFFF_FFFF) as u64)
}

fn normalize_http_request_for_policy(
    req: &[u8],
    host: &str,
    cfg: &SenderConfig,
) -> Result<Vec<u8>, String> {
    if req.len() == cfg.payload_len {
        return Ok(req.to_vec());
    }
    build_fixed_http_get(host, cfg.payload_len, cfg.host_offset)
}

fn build_fixed_http_get(host: &str, payload_len: usize, host_offset: usize) -> Result<Vec<u8>, String> {
    let prefix = b"GET / HTTP/1.1\r\n";
    if host_offset != prefix.len() {
        return Err(format!(
            "host_offset={} is unsupported for fixed GET template (expected {})",
            host_offset,
            prefix.len()
        ));
    }
    let mut out = Vec::new();
    out.extend_from_slice(prefix);
    out.extend_from_slice(b"Host: ");
    out.extend_from_slice(host.as_bytes());
    out.extend_from_slice(b"\r\nConnection: close\r\nX-Pad: ");
    if out.len() + 4 > payload_len {
        return Err("payload_len too small for fixed request".into());
    }
    let pad_len = payload_len - out.len() - 4;
    out.extend(core::iter::repeat_n(b'a', pad_len));
    out.extend_from_slice(b"\r\n\r\n");
    if out.len() != payload_len {
        return Err("failed to construct fixed payload length request".into());
    }
    Ok(out)
}

fn read_http_request(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp).map_err(|e| format!("read request: {e}"))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if find_header_end(&buf).is_some() {
            break;
        }
        if buf.len() > 1024 * 1024 {
            return Err("request too large".into());
        }
    }
    if buf.is_empty() {
        return Err("empty request".into());
    }

    let Some(header_end) = find_header_end(&buf) else {
        return Err("incomplete HTTP headers".into());
    };

    let content_len = parse_content_length(&buf[..header_end])?;
    let wanted = header_end + content_len;
    while buf.len() < wanted {
        let n = stream.read(&mut tmp).map_err(|e| format!("read body: {e}"))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    if buf.len() < wanted {
        return Err("incomplete HTTP body".into());
    }
    buf.truncate(wanted);
    Ok(buf)
}

fn parse_target(req: &[u8]) -> Result<(String, String, u16), String> {
    let req_str = std::str::from_utf8(req).map_err(|_| "request is not UTF-8 HTTP text")?;
    let mut lines = req_str.split("\r\n");
    let line = lines.next().ok_or("missing request line")?;
    let mut parts = line.split_whitespace();
    let method = parts.next().ok_or("missing method")?.to_string();
    let uri = parts.next().ok_or("missing URI")?;

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_host_port(uri, 443)?;
        return Ok((method, host, port));
    }

    if let Some(rest) = uri.strip_prefix("http://") {
        let authority = rest.split('/').next().ok_or("invalid absolute URI")?;
        let (host, port) = parse_host_port(authority, 80)?;
        return Ok((method, host, port));
    }

    for h in lines {
        if h.len() >= 5 && h.as_bytes()[..5].eq_ignore_ascii_case(b"host:") {
            let host = h[5..].trim();
            let (host, port) = parse_host_port(host, 80)?;
            return Ok((method, host, port));
        }
    }

    Err("missing Host header".into())
}

fn parse_host_port(s: &str, default_port: u16) -> Result<(String, u16), String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty host".into());
    }
    if let Some(rest) = s.strip_prefix('[') {
        let (inside, after) = rest
            .split_once(']')
            .ok_or("invalid IPv6 host, missing closing bracket")?;
        let port = if let Some(ps) = after.strip_prefix(':') {
            ps.parse::<u16>().map_err(|_| "invalid port")?
        } else {
            default_port
        };
        return Ok((inside.to_string(), port));
    }
    if let Some((host, port_str)) = s.rsplit_once(':') {
        if !host.contains(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                return Ok((host.to_string(), port));
            }
        }
    }
    Ok((s.to_string(), default_port))
}

fn parse_content_length(headers: &[u8]) -> Result<usize, String> {
    let s = std::str::from_utf8(headers).map_err(|_| "headers are not UTF-8")?;
    for line in s.split("\r\n") {
        if line.len() >= 15 && line.as_bytes()[..15].eq_ignore_ascii_case(b"content-length:") {
            let value = line[15..].trim();
            return value
                .parse::<usize>()
                .map_err(|_| "invalid Content-Length".to_string());
        }
    }
    Ok(0)
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
}

fn write_temp_request(req: &[u8]) -> Result<PathBuf, String> {
    let path = temp_path("hornet-proxy-req")?;
    fs::write(&path, req).map_err(|e| format!("write temp request: {e}"))?;
    Ok(path)
}

fn temp_path(prefix: &str) -> Result<PathBuf, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "clock error")?
        .as_nanos();
    Ok(PathBuf::from(format!("/tmp/{prefix}-{now}.bin")))
}

fn send_http_error(
    stream: &mut TcpStream,
    code: u16,
    reason: &str,
    body: &str,
) -> Result<(), String> {
    let resp = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream
        .write_all(resp.as_bytes())
        .map_err(|e| format!("write error response: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_origin_form_uses_host_header() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (method, host, port) = parse_target(req).expect("parse");
        assert_eq!(method, "GET");
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
    }

    #[test]
    fn parse_target_absolute_uri() {
        let req = b"GET http://example.com/path HTTP/1.1\r\nHost: ignored.invalid\r\n\r\n";
        let (_method, host, port) = parse_target(req).expect("parse");
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
    }

    #[test]
    fn parse_target_connect_tunnel() {
        let req = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        let (method, host, port) = parse_target(req).expect("parse");
        assert_eq!(method, "CONNECT");
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_content_length_zero_by_default() {
        let len = parse_content_length(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n").expect("len");
        assert_eq!(len, 0);
    }

    #[test]
    fn parse_content_length_value() {
        let len = parse_content_length(b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 12\r\n\r\n")
            .expect("len");
        assert_eq!(len, 12);
    }
}
