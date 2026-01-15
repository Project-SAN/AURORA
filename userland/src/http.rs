use crate::socket::{ConnectState, Error as SocketError, TcpSocket};
use crate::sys;
use core::arch::asm;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpError {
    Send,
    Recv,
    HeaderTooLarge,
    Malformed,
}

#[derive(Clone, Copy, Debug)]
pub struct HeaderInfo {
    pub status_code: u16,
    pub content_length: Option<usize>,
    pub header_end: usize,
}

const HEADER_MAX: usize = 2048;
const READ_BUF_SIZE: usize = 512;
const IDLE_LIMIT: u32 = 200;

pub fn http_get(ip: [u8; 4], port: u16, path: &str, host: &str) -> Result<(), HttpError> {
    let socket = TcpSocket::new();
    loop {
        match socket.connect(ip, port) {
            Ok(ConnectState::Connected) => break,
            Ok(ConnectState::InProgress) => {
                sys::sleep(10);
            }
            Err(_) => {
                let _ = socket.close();
                sys::sleep(10);
            }
        }
        unsafe { asm!("pause"); }
    }

    send_all(&socket, b"GET ")?;
    send_all(&socket, path.as_bytes())?;
    send_all(&socket, b" HTTP/1.1\r\nHost: ")?;
    send_all(&socket, host.as_bytes())?;
    send_all(
        &socket,
        b"\r\nUser-Agent: aurora\r\nConnection: close\r\n\r\n",
    )?;

    let mut header_buf = [0u8; HEADER_MAX];
    let mut header_len = 0usize;
    let mut parsed: Option<HeaderInfo> = None;
    let mut content_len: Option<usize> = None;
    let mut body_written = 0usize;
    let mut idle = 0u32;

    loop {
        let mut buf = [0u8; READ_BUF_SIZE];
        let n = match socket.recv(&mut buf) {
            Ok(n) => n,
            Err(_) => return Err(HttpError::Recv),
        };

        if n == 0 {
            idle += 1;
            if idle >= IDLE_LIMIT {
                break;
            }
            sys::sleep(10);
            unsafe { asm!("pause"); }
            continue;
        }
        idle = 0;

        if parsed.is_none() {
            if header_len + n > header_buf.len() {
                return Err(HttpError::HeaderTooLarge);
            }
            header_buf[header_len..header_len + n].copy_from_slice(&buf[..n]);
            header_len += n;
            match parse_headers(&header_buf[..header_len]) {
                Ok(None) => {}
                Ok(Some(info)) => {
                    parsed = Some(info);
                    content_len = info.content_length;
                    print_header_info(&info, &header_buf[..info.header_end]);
                    if header_len > info.header_end {
                        let mut body = &header_buf[info.header_end..header_len];
                        if let Some(total) = content_len {
                            let remaining = total.saturating_sub(body_written);
                            if body.len() > remaining {
                                body = &body[..remaining];
                            }
                        }
                        if !body.is_empty() {
                            let _ = sys::write(1, body);
                            body_written = body_written.saturating_add(body.len());
                        }
                    }
                }
                Err(_) => return Err(HttpError::Malformed),
            }
        } else {
            let mut body = &buf[..n];
            if let Some(total) = content_len {
                let remaining = total.saturating_sub(body_written);
                if remaining == 0 {
                    break;
                }
                if body.len() > remaining {
                    body = &body[..remaining];
                }
            }
            if !body.is_empty() {
                let _ = sys::write(1, body);
                body_written = body_written.saturating_add(body.len());
            }
        }

        if let Some(total) = content_len {
            if body_written >= total {
                break;
            }
        }
        unsafe { asm!("pause"); }
    }

    let _ = socket.close();
    Ok(())
}

fn send_all(socket: &TcpSocket, data: &[u8]) -> Result<(), HttpError> {
    let mut offset = 0usize;
    while offset < data.len() {
        match socket.send(&data[offset..]) {
            Ok(0) => {
                sys::sleep(10);
            }
            Ok(n) => {
                offset += n;
            }
            Err(SocketError::SysError) => return Err(HttpError::Send),
        }
        unsafe { asm!("pause"); }
    }
    Ok(())
}

fn parse_headers(buf: &[u8]) -> Result<Option<HeaderInfo>, HttpError> {
    let header_end = match find_header_end(buf) {
        Some(end) => end,
        None => return Ok(None),
    };
    let status_line_end = find_crlf(buf).ok_or(HttpError::Malformed)?;
    let status = parse_status_code(&buf[..status_line_end]).ok_or(HttpError::Malformed)?;
    let mut content_length: Option<usize> = None;

    let mut line_start = status_line_end + 2;
    while line_start + 1 < header_end {
        let line_end = match find_crlf(&buf[line_start..header_end]) {
            Some(rel) => line_start + rel,
            None => break,
        };
        let line = &buf[line_start..line_end];
        if let Some(len) = parse_content_length(line) {
            content_length = Some(len);
        }
        line_start = line_end + 2;
    }

    Ok(Some(HeaderInfo {
        status_code: status,
        content_length,
        header_end,
    }))
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    if buf.len() < 4 {
        return None;
    }
    let mut i = 0usize;
    while i + 3 < buf.len() {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' && buf[i + 2] == b'\r' && buf[i + 3] == b'\n'
        {
            return Some(i + 4);
        }
        i += 1;
    }
    None
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    let mut i = 0usize;
    while i + 1 < buf.len() {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn parse_status_code(line: &[u8]) -> Option<u16> {
    if line.len() < 12 || !line.starts_with(b"HTTP/") {
        return None;
    }
    let mut i = 0usize;
    while i < line.len() && line[i] != b' ' {
        i += 1;
    }
    if i + 4 > line.len() {
        return None;
    }
    let digits = &line[i + 1..i + 4];
    if !digits.iter().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let code = (digits[0] - b'0') as u16 * 100
        + (digits[1] - b'0') as u16 * 10
        + (digits[2] - b'0') as u16;
    Some(code)
}

fn parse_content_length(line: &[u8]) -> Option<usize> {
    const KEY: &[u8] = b"Content-Length:";
    if line.len() < KEY.len() {
        return None;
    }
    if !starts_with_ignore_ascii_case(line, KEY) {
        return None;
    }
    let mut i = KEY.len();
    while i < line.len() && (line[i] == b' ' || line[i] == b'\t') {
        i += 1;
    }
    if i >= line.len() {
        return None;
    }
    let mut value: usize = 0;
    let mut found = false;
    while i < line.len() {
        let b = line[i];
        if !b.is_ascii_digit() {
            break;
        }
        value = value.saturating_mul(10).saturating_add((b - b'0') as usize);
        found = true;
        i += 1;
    }
    if found { Some(value) } else { None }
}

fn starts_with_ignore_ascii_case(line: &[u8], prefix: &[u8]) -> bool {
    if line.len() < prefix.len() {
        return false;
    }
    for i in 0..prefix.len() {
        if to_lower(line[i]) != to_lower(prefix[i]) {
            return false;
        }
    }
    true
}

fn to_lower(b: u8) -> u8 {
    if b'A' <= b && b <= b'Z' {
        b + 32
    } else {
        b
    }
}

fn print_header_info(info: &HeaderInfo, raw: &[u8]) {
    let _ = sys::write(1, b"\n--- HTTP HEADER ---\n");
    let _ = sys::write(1, raw);
    let _ = sys::write(1, b"\n");
    let _ = sys::write(1, b"status=");
    write_decimal(info.status_code as usize);
    if let Some(len) = info.content_length {
        let _ = sys::write(1, b" content-length=");
        write_decimal(len);
    }
    let _ = sys::write(1, b"\n--- HTTP BODY ---\n");
}

fn write_decimal(mut value: usize) {
    let mut buf = [0u8; 20];
    let mut i = 0usize;
    if value == 0 {
        buf[0] = b'0';
        let _ = sys::write(1, &buf[..1]);
        return;
    }
    while value > 0 && i < buf.len() {
        let digit = (value % 10) as u8;
        buf[i] = b'0' + digit;
        value /= 10;
        i += 1;
    }
    buf[..i].reverse();
    let _ = sys::write(1, &buf[..i]);
}
