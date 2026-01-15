use crate::socket::{ConnectState, Error as SocketError, TcpSocket};
use crate::sys;
use core::arch::asm;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpError {
    Socket,
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
    pub chunked: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct HttpResponse {
    pub status_code: u16,
    pub content_length: Option<usize>,
    pub chunked: bool,
}

const HEADER_MAX: usize = 2048;
const CHUNK_LINE_MAX: usize = 32;
const READ_BUF_SIZE: usize = 512;
const IDLE_LIMIT: u32 = 200;
const CHUNK_PENDING_MAX: usize = CHUNK_LINE_MAX + 2;
const CHUNK_SCRATCH_MAX: usize = HEADER_MAX + CHUNK_PENDING_MAX;

pub trait BodySink {
    fn on_data(&mut self, data: &[u8]);
}

pub struct StdoutSink;

impl BodySink for StdoutSink {
    fn on_data(&mut self, data: &[u8]) {
        let _ = sys::write(1, data);
    }
}

#[derive(Clone, Copy, Debug)]
pub enum ClientPoll {
    InProgress,
    Done(HttpResponse),
    Error(HttpError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClientState {
    Connecting,
    Sending,
    Receiving,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SendPhase {
    Get,
    Path,
    Proto,
    HostHeader,
    Host,
    Tail,
    Done,
}

pub struct HttpClient {
    ip: [u8; 4],
    port: u16,
    path: &'static str,
    host: &'static str,
    socket: TcpSocket,
    state: ClientState,
    send_phase: SendPhase,
    send_off: usize,
    header_buf: [u8; HEADER_MAX],
    header_len: usize,
    parsed: Option<HeaderInfo>,
    content_len: Option<usize>,
    chunked: bool,
    body_written: usize,
    idle: u32,
    chunk: ChunkDecoder,
    pending: [u8; CHUNK_PENDING_MAX],
    pending_len: usize,
    sink: StdoutSink,
    done: Option<HttpResponse>,
    error: Option<HttpError>,
}

impl HttpClient {
    pub fn new(
        ip: [u8; 4],
        port: u16,
        path: &'static str,
        host: &'static str,
    ) -> Result<Self, HttpError> {
        let socket = TcpSocket::new().map_err(|_| HttpError::Socket)?;
        Ok(Self {
            ip,
            port,
            path,
            host,
            socket,
            state: ClientState::Connecting,
            send_phase: SendPhase::Get,
            send_off: 0,
            header_buf: [0u8; HEADER_MAX],
            header_len: 0,
            parsed: None,
            content_len: None,
            chunked: false,
            body_written: 0,
            idle: 0,
            chunk: ChunkDecoder::new(),
            pending: [0u8; CHUNK_PENDING_MAX],
            pending_len: 0,
            sink: StdoutSink,
            done: None,
            error: None,
        })
    }

    pub fn poll(&mut self) -> ClientPoll {
        if let Some(resp) = self.done {
            return ClientPoll::Done(resp);
        }
        if let Some(err) = self.error {
            return ClientPoll::Error(err);
        }

        match self.state {
            ClientState::Connecting => {
                match self.socket.connect(self.ip, self.port) {
                    Ok(ConnectState::Connected) => {
                        self.state = ClientState::Sending;
                    }
                    Ok(ConnectState::InProgress) => {
                        return ClientPoll::InProgress;
                    }
                    Err(_) => {
                        self.error = Some(HttpError::Send);
                        return ClientPoll::Error(HttpError::Send);
                    }
                }
            }
            ClientState::Sending => {
                match self.poll_send() {
                    Ok(true) => {
                        self.state = ClientState::Receiving;
                    }
                    Ok(false) => return ClientPoll::InProgress,
                    Err(err) => {
                        self.error = Some(err);
                        return ClientPoll::Error(err);
                    }
                }
            }
            ClientState::Receiving => {
                match self.poll_recv() {
                    Ok(Some(resp)) => {
                        self.done = Some(resp);
                        return ClientPoll::Done(resp);
                    }
                    Ok(None) => return ClientPoll::InProgress,
                    Err(err) => {
                        self.error = Some(err);
                        return ClientPoll::Error(err);
                    }
                }
            }
        }
        ClientPoll::InProgress
    }

    fn poll_send(&mut self) -> Result<bool, HttpError> {
        loop {
            let data = match self.send_phase {
                SendPhase::Get => b"GET " as &[u8],
                SendPhase::Path => self.path.as_bytes(),
                SendPhase::Proto => b" HTTP/1.1\r\nHost: ",
                SendPhase::HostHeader => b"",
                SendPhase::Host => self.host.as_bytes(),
                SendPhase::Tail => b"\r\nUser-Agent: aurora\r\nConnection: close\r\n\r\n",
                SendPhase::Done => return Ok(true),
            };

            if self.send_phase == SendPhase::HostHeader {
                self.send_phase = SendPhase::Host;
                self.send_off = 0;
                continue;
            }

            if self.send_off >= data.len() {
                self.send_phase = match self.send_phase {
                    SendPhase::Get => SendPhase::Path,
                    SendPhase::Path => SendPhase::Proto,
                    SendPhase::Proto => SendPhase::HostHeader,
                    SendPhase::Host => SendPhase::Tail,
                    SendPhase::Tail => SendPhase::Done,
                    SendPhase::HostHeader => SendPhase::Host,
                    SendPhase::Done => SendPhase::Done,
                };
                self.send_off = 0;
                continue;
            }

            match self.socket.send(&data[self.send_off..]) {
                Ok(0) => return Ok(false),
                Ok(n) => {
                    self.send_off += n;
                }
                Err(_) => return Err(HttpError::Send),
            }
        }
    }

    fn poll_recv(&mut self) -> Result<Option<HttpResponse>, HttpError> {
        let mut buf = [0u8; READ_BUF_SIZE];
        let n = match self.socket.recv(&mut buf) {
            Ok(n) => n,
            Err(_) => return Err(HttpError::Recv),
        };

        if n == 0 {
            self.idle += 1;
            if self.idle >= IDLE_LIMIT {
                if let Some(info) = self.parsed {
                    let resp = HttpResponse {
                        status_code: info.status_code,
                        content_length: info.content_length,
                        chunked: self.chunked,
                    };
                    let _ = self.socket.close();
                    return Ok(Some(resp));
                }
            }
            return Ok(None);
        }
        self.idle = 0;

        if self.parsed.is_none() {
            if self.header_len + n > self.header_buf.len() {
                return Err(HttpError::HeaderTooLarge);
            }
            self.header_buf[self.header_len..self.header_len + n].copy_from_slice(&buf[..n]);
            self.header_len += n;
            match parse_headers(&self.header_buf[..self.header_len]) {
                Ok(None) => {}
                Ok(Some(info)) => {
                    self.chunked = info.chunked;
                    self.parsed = Some(info);
                    self.content_len = if info.chunked { None } else { info.content_length };
                    if self.header_len > info.header_end {
                        let body = &self.header_buf[info.header_end..self.header_len];
                        if self.chunked {
                            if consume_chunked(
                                &mut self.chunk,
                                &mut self.pending,
                                &mut self.pending_len,
                                body,
                                &mut self.sink,
                            )? {
                                let resp = HttpResponse {
                                    status_code: info.status_code,
                                    content_length: info.content_length,
                                    chunked: true,
                                };
                                let _ = self.socket.close();
                                return Ok(Some(resp));
                            }
                        } else {
                            let mut body = body;
                            if let Some(total) = self.content_len {
                                let remaining = total.saturating_sub(self.body_written);
                                if body.len() > remaining {
                                    body = &body[..remaining];
                                }
                            }
                            if !body.is_empty() {
                                self.sink.on_data(body);
                                self.body_written = self.body_written.saturating_add(body.len());
                            }
                        }
                    }
                }
                Err(_) => return Err(HttpError::Malformed),
            }
        } else {
            let mut body = &buf[..n];
            if self.chunked {
                if consume_chunked(
                    &mut self.chunk,
                    &mut self.pending,
                    &mut self.pending_len,
                    body,
                    &mut self.sink,
                )? {
                    let info = self.parsed.ok_or(HttpError::Malformed)?;
                    let resp = HttpResponse {
                        status_code: info.status_code,
                        content_length: info.content_length,
                        chunked: true,
                    };
                    let _ = self.socket.close();
                    return Ok(Some(resp));
                }
            } else {
                if let Some(total) = self.content_len {
                    let remaining = total.saturating_sub(self.body_written);
                    if remaining == 0 {
                        let info = self.parsed.ok_or(HttpError::Malformed)?;
                        let resp = HttpResponse {
                            status_code: info.status_code,
                            content_length: info.content_length,
                            chunked: false,
                        };
                        let _ = self.socket.close();
                        return Ok(Some(resp));
                    }
                    if body.len() > remaining {
                        body = &body[..remaining];
                    }
                }
                if !body.is_empty() {
                    self.sink.on_data(body);
                    self.body_written = self.body_written.saturating_add(body.len());
                }
                if let Some(total) = self.content_len {
                    if self.body_written >= total {
                        let info = self.parsed.ok_or(HttpError::Malformed)?;
                        let resp = HttpResponse {
                            status_code: info.status_code,
                            content_length: info.content_length,
                            chunked: false,
                        };
                        let _ = self.socket.close();
                        return Ok(Some(resp));
                    }
                }
            }
        }
        Ok(None)
    }
}

#[allow(dead_code)]
pub fn http_get(
    ip: [u8; 4],
    port: u16,
    path: &str,
    host: &str,
) -> Result<HttpResponse, HttpError> {
    let mut sink = StdoutSink;
    http_get_with(ip, port, path, host, &mut sink)
}

#[allow(dead_code)]
pub fn http_get_with<S: BodySink>(
    ip: [u8; 4],
    port: u16,
    path: &str,
    host: &str,
    sink: &mut S,
) -> Result<HttpResponse, HttpError> {
    let socket = TcpSocket::new().map_err(|_| HttpError::Socket)?;
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
    let mut chunked = false;
    let mut body_written = 0usize;
    let mut idle = 0u32;
    let mut chunk = ChunkDecoder::new();
    let mut pending = [0u8; CHUNK_PENDING_MAX];
    let mut pending_len = 0usize;

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
                    chunked = info.chunked;
                    parsed = Some(info);
                    content_len = if info.chunked { None } else { info.content_length };
                    if header_len > info.header_end {
                        let body = &header_buf[info.header_end..header_len];
                        if chunked {
                            if consume_chunked(&mut chunk, &mut pending, &mut pending_len, body, sink)? {
                                break;
                            }
                        } else {
                            let mut body = body;
                            if let Some(total) = content_len {
                                let remaining = total.saturating_sub(body_written);
                                if body.len() > remaining {
                                    body = &body[..remaining];
                                }
                            }
                            if !body.is_empty() {
                                sink.on_data(body);
                                body_written = body_written.saturating_add(body.len());
                            }
                        }
                    }
                }
                Err(_) => return Err(HttpError::Malformed),
            }
        } else {
            let mut body = &buf[..n];
            if chunked {
                if consume_chunked(&mut chunk, &mut pending, &mut pending_len, body, sink)? {
                    break;
                }
            } else {
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
                    sink.on_data(body);
                    body_written = body_written.saturating_add(body.len());
                }
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
    let info = parsed.ok_or(HttpError::Malformed)?;
    Ok(HttpResponse {
        status_code: info.status_code,
        content_length: info.content_length,
        chunked,
    })
}

#[allow(dead_code)]
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

fn consume_chunked<S: BodySink>(
    chunk: &mut ChunkDecoder,
    pending: &mut [u8; CHUNK_PENDING_MAX],
    pending_len: &mut usize,
    data: &[u8],
    sink: &mut S,
) -> Result<bool, HttpError> {
    let mut scratch = [0u8; CHUNK_SCRATCH_MAX];
    let mut total = 0usize;
    if *pending_len > 0 {
        scratch[..*pending_len].copy_from_slice(&pending[..*pending_len]);
        total = *pending_len;
        *pending_len = 0;
    }
    if total + data.len() > scratch.len() {
        return Err(HttpError::HeaderTooLarge);
    }
    scratch[total..total + data.len()].copy_from_slice(data);
    total += data.len();

    let used = chunk.consume(&scratch[..total], sink)?;
    if used < total {
        let remaining = total - used;
        if remaining > pending.len() {
            return Err(HttpError::HeaderTooLarge);
        }
        pending[..remaining].copy_from_slice(&scratch[used..total]);
        *pending_len = remaining;
    }
    Ok(chunk.is_done())
}

fn parse_headers(buf: &[u8]) -> Result<Option<HeaderInfo>, HttpError> {
    let header_end = match find_header_end(buf) {
        Some(end) => end,
        None => return Ok(None),
    };
    let status_line_end = find_crlf(buf).ok_or(HttpError::Malformed)?;
    let status = parse_status_code(&buf[..status_line_end]).ok_or(HttpError::Malformed)?;
    let mut content_length: Option<usize> = None;
    let mut chunked = false;

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
        if parse_transfer_encoding_chunked(line) {
            chunked = true;
        }
        line_start = line_end + 2;
    }

    Ok(Some(HeaderInfo {
        status_code: status,
        content_length,
        header_end,
        chunked,
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

fn parse_transfer_encoding_chunked(line: &[u8]) -> bool {
    const KEY: &[u8] = b"Transfer-Encoding:";
    if line.len() < KEY.len() {
        return false;
    }
    if !starts_with_ignore_ascii_case(line, KEY) {
        return false;
    }
    let mut i = KEY.len();
    while i < line.len() && (line[i] == b' ' || line[i] == b'\t') {
        i += 1;
    }
    if i >= line.len() {
        return false;
    }
    contains_token_ignore_ascii_case(&line[i..], b"chunked")
}

fn contains_token_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    let mut i = 0usize;
    while i + needle.len() <= haystack.len() {
        let mut matched = true;
        for j in 0..needle.len() {
            if to_lower(haystack[i + j]) != to_lower(needle[j]) {
                matched = false;
                break;
            }
        }
        if matched {
            return true;
        }
        i += 1;
    }
    false
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

pub fn print_response(resp: &HttpResponse) {
    let _ = sys::write(1, b"\n--- HTTP RESPONSE ---\n");
    let _ = sys::write(1, b"status=");
    write_decimal(resp.status_code as usize);
    if let Some(len) = resp.content_length {
        let _ = sys::write(1, b" content-length=");
        write_decimal(len);
    }
    if resp.chunked {
        let _ = sys::write(1, b" transfer-encoding=chunked");
    }
    let _ = sys::write(1, b"\n--- HTTP BODY ---\n");
}

pub fn print_error(err: HttpError) {
    let _ = sys::write(1, b"\nHTTP error: ");
    match err {
        HttpError::Socket => { let _ = sys::write(1, b"socket"); }
        HttpError::Send => { let _ = sys::write(1, b"send"); }
        HttpError::Recv => { let _ = sys::write(1, b"recv"); }
        HttpError::HeaderTooLarge => { let _ = sys::write(1, b"header-too-large"); }
        HttpError::Malformed => { let _ = sys::write(1, b"malformed"); }
    }
    let _ = sys::write(1, b"\n");
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

struct ChunkDecoder {
    state: ChunkState,
    line: [u8; CHUNK_LINE_MAX],
    line_len: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChunkState {
    Size,
    Data { remaining: usize },
    CrLf,
    Done,
}

impl ChunkDecoder {
    fn new() -> Self {
        Self {
            state: ChunkState::Size,
            line: [0u8; CHUNK_LINE_MAX],
            line_len: 0,
        }
    }

    fn is_done(&self) -> bool {
        self.state == ChunkState::Done
    }

    fn consume<S: BodySink>(&mut self, mut data: &[u8], sink: &mut S) -> Result<usize, HttpError> {
        let original_len = data.len();
        while !data.is_empty() {
            match self.state {
                ChunkState::Size => {
                    while !data.is_empty() {
                        if self.line_len >= self.line.len() {
                            return Err(HttpError::HeaderTooLarge);
                        }
                        let b = data[0];
                        self.line[self.line_len] = b;
                        self.line_len += 1;
                        data = &data[1..];
                        if self.line_len >= 2
                            && self.line[self.line_len - 2] == b'\r'
                            && self.line[self.line_len - 1] == b'\n'
                        {
                            let line = &self.line[..self.line_len - 2];
                            let size = parse_chunk_size(line).ok_or(HttpError::Malformed)?;
                            self.line_len = 0;
                            if size == 0 {
                                self.state = ChunkState::Done;
                                return Ok(original_len - data.len());
                            }
                            self.state = ChunkState::Data { remaining: size };
                            break;
                        }
                    }
                }
                ChunkState::Data { remaining } => {
                    let take = core::cmp::min(remaining, data.len());
                    if take > 0 {
                        sink.on_data(&data[..take]);
                        data = &data[take..];
                    }
                    let left = remaining - take;
                    if left == 0 {
                        self.state = ChunkState::CrLf;
                    } else {
                        self.state = ChunkState::Data { remaining: left };
                    }
                }
                ChunkState::CrLf => {
                    if data.len() < 2 {
                        break;
                    }
                    if data[0] != b'\r' || data[1] != b'\n' {
                        return Err(HttpError::Malformed);
                    }
                    data = &data[2..];
                    self.state = ChunkState::Size;
                }
                ChunkState::Done => {
                    return Ok(original_len - data.len());
                }
            }
        }
        Ok(original_len - data.len())
    }
}

fn parse_chunk_size(line: &[u8]) -> Option<usize> {
    let mut i = 0usize;
    while i < line.len() && (line[i] == b' ' || line[i] == b'\t') {
        i += 1;
    }
    let mut value: usize = 0;
    let mut found = false;
    while i < line.len() {
        let b = line[i];
        if b == b';' || b == b' ' || b == b'\t' {
            break;
        }
        let digit = hex_value(b)?;
        value = value.saturating_mul(16).saturating_add(digit as usize);
        found = true;
        i += 1;
    }
    if found { Some(value) } else { None }
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
