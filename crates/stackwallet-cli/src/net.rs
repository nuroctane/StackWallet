//! Blocking TCP carrier for `transport::Session`.
//!
//! The session is sans-IO; this module moves its ciphertexts over a socket as
//! `u16` big-endian length-prefixed records (Noise caps a message at 65535
//! bytes, so the prefix can never truncate one). One reader thread per
//! connection pushes raw records into a channel and the thread that owns the
//! sessions drains it, so session state never crosses threads and a hub
//! talking to several peers needs no async runtime.

use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::time::{Duration, Instant};

use stackwallet_core::transport::{Frame, Session, SessionEvent, SessionState};

/// A peer that sends nothing for this long is treated as gone. Ceremonies
/// are a handful of round trips, so a stall this long means the other side
/// crashed or walked away, and holding the socket open would only keep a
/// half-finished ceremony (and its vault) hostage.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long an initiator keeps retrying a refused connection, so a peer that
/// is still starting its `serve` loop does not fail the whole ceremony.
pub const CONNECT_RETRY: Duration = Duration::from_secs(10);

/// A connection that has not finished the Noise handshake and Hello exchange by
/// now never will; anything longer lets one silent socket stall a sequential
/// accept loop. Raised to `IDLE_TIMEOUT` once the session opens.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

const MAX_RECORD: usize = u16::MAX as usize;

pub fn write_record(stream: &mut TcpStream, bytes: &[u8]) -> std::io::Result<()> {
    if bytes.len() > MAX_RECORD {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            format!("record of {} bytes exceeds {MAX_RECORD}", bytes.len()),
        ));
    }
    let mut buf = Vec::with_capacity(2 + bytes.len());
    buf.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(bytes);
    stream.write_all(&buf)?;
    stream.flush()
}

/// `Ok(None)` is a clean end of stream before any byte of the next record.
pub fn read_record(stream: &mut TcpStream) -> std::io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 2];
    match stream.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
    stream.read_exact(&mut body)?;
    Ok(Some(body))
}

/// Connect to the first address that answers, retrying refusals until
/// `retry_for` elapses.
pub fn connect_with_retry(addrs: &[String], retry_for: Duration) -> Result<TcpStream, String> {
    if addrs.is_empty() {
        return Err("no address to connect to".into());
    }
    let deadline = Instant::now() + retry_for;
    let mut last_error = String::new();
    loop {
        for addr in addrs {
            let resolved = match addr.to_socket_addrs() {
                Ok(it) => it.collect::<Vec<SocketAddr>>(),
                Err(e) => {
                    last_error = format!("{addr}: {e}");
                    continue;
                }
            };
            for sa in resolved {
                match TcpStream::connect_timeout(&sa, Duration::from_secs(5)) {
                    Ok(stream) => return Ok(stream),
                    Err(e) => last_error = format!("{sa}: {e}"),
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(format!("could not connect: {last_error}"));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

enum Inbound {
    Record(Vec<u8>),
    Eof,
    Error(String),
}

struct Conn {
    stream: TcpStream,
    session: Session,
    peer_addr: SocketAddr,
    /// Set once a `Closed` event has been surfaced so a later reader error
    /// does not produce a second one.
    closed_reported: bool,
    /// Whether the read timeout was raised to ``IDLE_TIMEOUT`` after the
    /// session opened. The socket options live on the shared handle, so the
    /// reader thread's clone sees the new value.
    timeout_raised: bool,
}

/// Every open connection of one process plus the events they produced.
pub struct Hub {
    conns: Vec<Conn>,
    tx: Sender<(usize, Inbound)>,
    rx: Receiver<(usize, Inbound)>,
    pending: VecDeque<(usize, SessionEvent)>,
}

impl Default for Hub {
    fn default() -> Self {
        Self::new()
    }
}

impl Hub {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel();
        Self {
            conns: Vec::new(),
            tx,
            rx,
            pending: VecDeque::new(),
        }
    }

    /// Adopt a connected socket and its session, start reading from it, and
    /// send whatever the session already queued (an initiator's first
    /// handshake message). Returns the index later events refer to.
    pub fn add(&mut self, stream: TcpStream, session: Session) -> Result<usize, String> {
        let peer_addr = stream.peer_addr().map_err(|e| e.to_string())?;
        stream.set_nodelay(true).map_err(|e| e.to_string())?;
        let reader = stream.try_clone().map_err(|e| e.to_string())?;
        reader
            .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
            .map_err(|e| e.to_string())?;
        let idx = self.conns.len();
        self.conns.push(Conn {
            stream,
            session,
            peer_addr,
            closed_reported: false,
            timeout_raised: false,
        });
        let tx = self.tx.clone();
        std::thread::spawn(move || read_loop(idx, reader, tx));
        self.flush(idx)?;
        Ok(idx)
    }

    pub fn all_closed(&self) -> bool {
        self.conns
            .iter()
            .all(|c| c.session.state() == SessionState::Closed)
    }

    pub fn send(&mut self, idx: usize, frame: Frame) -> Result<(), String> {
        self.conns[idx]
            .session
            .send(frame)
            .map_err(|e| format!("send to {}: {e}", self.conns[idx].peer_addr))?;
        self.flush(idx)
    }

    /// Close one session, pushing whatever the session wants to say last
    /// (a `Bye`, if it emits one) before shutting the socket.
    pub fn close(&mut self, idx: usize, reason: &str) {
        let conn = &mut self.conns[idx];
        if conn.session.state() != SessionState::Closed {
            conn.session.close(reason);
        }
        let _ = self.flush(idx);
        let _ = self.conns[idx].stream.shutdown(Shutdown::Both);
        self.conns[idx].closed_reported = true;
    }

    pub fn close_all(&mut self, reason: &str) {
        for idx in 0..self.conns.len() {
            self.close(idx, reason);
        }
    }

    /// The next event from any connection. `Ok(None)` once every session is
    /// closed and nothing is queued; `Err` when nothing arrived within
    /// `timeout`, which callers treat as the peer having stalled.
    pub fn next_event(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<(usize, SessionEvent)>, String> {
        loop {
            if let Some(ev) = self.pending.pop_front() {
                return Ok(Some(ev));
            }
            if !self.conns.is_empty() && self.all_closed() {
                return Ok(None);
            }
            let (idx, inbound) = match self.rx.recv_timeout(timeout) {
                Ok(item) => item,
                Err(RecvTimeoutError::Timeout) => {
                    return Err(format!("no traffic for {}s", timeout.as_secs()))
                }
                Err(RecvTimeoutError::Disconnected) => return Ok(None),
            };
            match inbound {
                Inbound::Record(bytes) => {
                    let conn = &mut self.conns[idx];
                    if conn.session.state() == SessionState::Closed {
                        continue;
                    }
                    match conn.session.handle_incoming(&bytes) {
                        Ok(events) => {
                            for ev in events {
                                if matches!(ev, SessionEvent::Closed { .. }) {
                                    conn.closed_reported = true;
                                }
                                self.pending.push_back((idx, ev));
                            }
                        }
                        Err(e) => self.fail(idx, e.to_string()),
                    }
                    if let Err(e) = self.flush(idx) {
                        self.fail(idx, e);
                    }
                    self.raise_timeout_once_open(idx);
                }
                Inbound::Eof => self.fail(idx, "peer closed the connection".into()),
                Inbound::Error(e) => self.fail(idx, e),
            }
        }
    }

    /// Sessions start on the short handshake budget; once open they get the
    /// full idle allowance ceremonies need.
    fn raise_timeout_once_open(&mut self, idx: usize) {
        let conn = &mut self.conns[idx];
        if !conn.timeout_raised && conn.session.state() == SessionState::Open {
            let _ = conn.stream.set_read_timeout(Some(IDLE_TIMEOUT));
            conn.timeout_raised = true;
        }
    }

    fn fail(&mut self, idx: usize, reason: String) {
        let conn = &mut self.conns[idx];
        if conn.closed_reported {
            return;
        }
        conn.session.close(&reason);
        let _ = conn.stream.shutdown(Shutdown::Both);
        conn.closed_reported = true;
        self.pending
            .push_back((idx, SessionEvent::Closed { reason }));
    }

    fn flush(&mut self, idx: usize) -> Result<(), String> {
        let conn = &mut self.conns[idx];
        for record in conn.session.take_outgoing() {
            write_record(&mut conn.stream, &record)
                .map_err(|e| format!("write to {}: {e}", conn.peer_addr))?;
        }
        Ok(())
    }
}

impl Drop for Hub {
    fn drop(&mut self) {
        // Reader threads block in `read_exact` on their clone of the socket;
        // shutting the socket down is what makes them return.
        for conn in &self.conns {
            let _ = conn.stream.shutdown(Shutdown::Both);
        }
    }
}

fn read_loop(idx: usize, mut stream: TcpStream, tx: Sender<(usize, Inbound)>) {
    loop {
        let item = match read_record(&mut stream) {
            Ok(Some(bytes)) => Inbound::Record(bytes),
            Ok(None) => Inbound::Eof,
            Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                Inbound::Error("read timed out".into())
            }
            Err(e) => Inbound::Error(e.to_string()),
        };
        let done = !matches!(item, Inbound::Record(_));
        if tx.send((idx, item)).is_err() || done {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn records_round_trip_and_eof_is_clean() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let writer = std::thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            write_record(&mut s, b"").unwrap();
            write_record(&mut s, &[7u8; 300]).unwrap();
            assert!(write_record(&mut s, &vec![0u8; MAX_RECORD + 1]).is_err());
        });
        let (mut s, _) = listener.accept().unwrap();
        assert_eq!(read_record(&mut s).unwrap(), Some(Vec::new()));
        assert_eq!(read_record(&mut s).unwrap(), Some(vec![7u8; 300]));
        writer.join().unwrap();
        assert_eq!(read_record(&mut s).unwrap(), None);
    }

    #[test]
    fn connect_retry_gives_up_with_the_last_error() {
        // A freed port can be grabbed by another process before the first
        // attempt, so exercise the retry loop with an address that never
        // resolves instead of racing the OS.
        let err = connect_with_retry(&["not-an-addr".to_owned()], Duration::from_millis(300))
            .unwrap_err();
        assert!(err.contains("could not connect"), "{err}");
    }
}
