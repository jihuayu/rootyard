//! PTY control for a running sandbox. Output is drained even without a client.
use crate::Error;
use axum::http::StatusCode;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{collections::HashMap, fs::File, io::{Read, Write}, os::{fd::{AsRawFd, FromRawFd}, unix::fs::OpenOptionsExt},
    sync::{Arc, Mutex, OnceLock}, thread};
use uuid::Uuid;

const OUTPUT_LIMIT: usize = 256 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input { pub data_base64: String }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputQuery { pub offset: Option<u64> }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resize { pub rows: u16, pub columns: u16 }

pub(super) fn write_input(id: Uuid, input: Input) -> Result<Value, Error> {
    if input.data_base64.len() > 5500 { return Err(Error::bad_request()); }
    let data = STANDARD.decode(input.data_base64).map_err(|_| Error::bad_request())?;
    let accepted = self::input(id, &data)?;
    Ok(json!({"accepted_bytes": accepted}))
}
pub(super) fn read_output(path: &std::path::Path, query: OutputQuery) -> Result<Value, Error> {
    let (bytes, next_offset) = output(path, query.offset.unwrap_or(0))?;
    Ok(json!({"data_base64": STANDARD.encode(bytes), "next_offset": next_offset,
        "output_limit_bytes": OUTPUT_LIMIT}))
}

struct Control { writer: Mutex<File> }
static LIVE: OnceLock<Mutex<HashMap<Uuid, Arc<Control>>>> = OnceLock::new();
fn live() -> &'static Mutex<HashMap<Uuid, Arc<Control>>> {
    LIVE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(super) struct Pty { pub slave: File, reader: File, control: Arc<Control> }
impl Pty {
    pub(super) fn open() -> Result<Self, Error> {
        let (mut master, mut slave) = (-1, -1);
        let size = libc::winsize { ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0 };
        if unsafe { libc::openpty(&mut master, &mut slave, std::ptr::null_mut(),
            std::ptr::null(), &size) } != 0 {
            return Err(Error::internal(std::io::Error::last_os_error()));
        }
        let master = unsafe { File::from_raw_fd(master) };
        let slave = unsafe { File::from_raw_fd(slave) };
        let flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(Error::internal(std::io::Error::last_os_error()));
        }
        let writer = master.try_clone().map_err(Error::internal)?;
        Ok(Self { slave, reader: master, control: Arc::new(Control { writer: Mutex::new(writer) }) })
    }

    pub(super) fn drain(self, id: Uuid, mut output: File) {
        live().lock().expect("terminal registry").insert(id, self.control);
        thread::spawn(move || {
            let mut reader = self.reader;
            let mut buf = [0u8; 8192];
            let mut written = 0usize;
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(_) => break,
                    Ok(size) => {
                        let keep = size.min(OUTPUT_LIMIT.saturating_sub(written));
                        if keep > 0 {
                            if output.write_all(&buf[..keep]).is_err() { break; }
                            written += keep;
                        }
                    }
                }
            }
            let _ = output.sync_all();
            live().lock().expect("terminal registry").remove(&id);
        });
    }
}

pub(super) fn close(id: Uuid) {
    live().lock().expect("terminal registry").remove(&id);
}
pub(super) fn input(id: Uuid, bytes: &[u8]) -> Result<usize, Error> {
    if bytes.is_empty() || bytes.len() > 4096 { return Err(Error::bad_request()); }
    let control = live().lock().expect("terminal registry").get(&id).cloned()
        .ok_or_else(|| Error(StatusCode::CONFLICT, "terminal is not running on this host"))?;
    match control.writer.lock().expect("terminal writer").write(bytes) {
        Ok(0) => Err(Error(StatusCode::TOO_MANY_REQUESTS,"terminal input backpressure")),
        Ok(written) => Ok(written),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock =>
            Err(Error(StatusCode::TOO_MANY_REQUESTS,"terminal input backpressure")),
        Err(error) => Err(Error::internal(error)),
    }
}
pub(super) fn resize(id: Uuid, rows: u16, columns: u16) -> Result<(), Error> {
    if !(1..=200).contains(&rows) || !(1..=300).contains(&columns) {
        return Err(Error::bad_request());
    }
    let control = live().lock().expect("terminal registry").get(&id).cloned()
        .ok_or_else(|| Error(StatusCode::CONFLICT, "terminal is not running on this host"))?;
    let size = libc::winsize { ws_row: rows, ws_col: columns, ws_xpixel: 0, ws_ypixel: 0 };
    let file = control.writer.lock().expect("terminal writer");
    if unsafe { libc::ioctl(file.as_raw_fd(), libc::TIOCSWINSZ, &size) } != 0 {
        return Err(Error::internal(std::io::Error::last_os_error()));
    }
    Ok(())
}

pub(super) fn output(path: &std::path::Path, offset: u64) -> Result<(Vec<u8>, u64), Error> {
    let file = match std::fs::OpenOptions::new().read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), 0)),
        Err(error) => return Err(Error::internal(error)),
    };
    if !file.metadata().map_err(Error::internal)?.is_file() {
        return Err(Error::not_found());
    }
    let end = file.metadata().map_err(Error::internal)?.len().min(OUTPUT_LIMIT as u64);
    let start = offset.min(end);
    let mut buf = vec![0u8; (end - start).min(8192) as usize];
    use std::os::unix::fs::FileExt;
    let read = file.read_at(&mut buf, start).map_err(Error::internal)?;
    buf.truncate(read);
    Ok((buf, start + read as u64))
}
