//! VM execution module for `hypr exec` functionality.
//!
//! This module provides the ability to execute commands inside running VMs,
//! similar to `docker exec`. Communication happens over vsock (virtio socket).
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐     vsock      ┌─────────────────┐
//! │   Host (hypr)   │ ──────────────►│   Guest (VM)    │
//! │                 │                │                 │
//! │  ExecClient     │  CID:3:1024    │  Kestrel Agent  │
//! │  ├─ send_exec() │◄──────────────►│  ├─ listen()    │
//! │  ├─ send_stdin()│                │  ├─ spawn()     │
//! │  └─ recv_output │                │  └─ relay I/O   │
//! └─────────────────┘                └─────────────────┘
//! ```
//!
//! # Protocol
//!
//! The protocol is a simple length-prefixed binary format:
//!
//! ```text
//! ┌────────────┬──────────┬─────────────┬─────────────┐
//! │ Length (4) │ Type (1) │ Session (4) │ Payload ... │
//! └────────────┴──────────┴─────────────┴─────────────┘
//! ```

mod protocol;

pub use protocol::{ExecMessage, ExecRequest, ExecResponse, MessageType};

use crate::error::{HyprError, Result};
use std::path::Path;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tracing::debug;

/// Default vsock port for exec server in guest.
pub const EXEC_VSOCK_PORT: u32 = 1024;

/// Guest CID for vsock (standard guest CID).
pub const GUEST_CID: u32 = 3;

/// Client for executing commands in a VM via vsock.
pub struct ExecClient {
    /// Path to the vsock Unix socket exposed by the hypervisor
    socket_path: std::path::PathBuf,
    /// Current session ID
    session_id: u32,
}

impl ExecClient {
    /// Create a new exec client for the given VM.
    ///
    /// The vsock_path should be the Unix socket exposed by the hypervisor
    /// that bridges to the guest's vsock.
    pub fn new(vsock_path: impl AsRef<Path>) -> Self {
        Self { socket_path: vsock_path.as_ref().to_path_buf(), session_id: rand_session_id() }
    }

    /// Execute a command in the VM and return the exit code.
    ///
    /// This is a simple blocking execution - the command runs and we wait
    /// for it to complete. For interactive sessions, use `exec_interactive`.
    pub async fn exec(&mut self, cmd: &str, env: Vec<(String, String)>) -> Result<i32> {
        debug!("Connecting to VM via vsock: {}", self.socket_path.display());

        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(|e| HyprError::Internal(format!("Failed to connect to VM vsock: {}", e)))?;

        // Send exec request
        let request = ExecRequest {
            session_id: self.session_id,
            command: cmd.to_string(),
            env,
            tty: false,
            rows: 0,
            cols: 0,
        };

        let msg = ExecMessage::ExecRequest(request);
        send_message(&mut stream, &msg).await?;

        // Wait for response
        loop {
            let response = recv_message(&mut stream).await?;

            match response {
                ExecMessage::Stdout(data) => {
                    print!("{}", String::from_utf8_lossy(&data));
                }
                ExecMessage::Stderr(data) => {
                    eprint!("{}", String::from_utf8_lossy(&data));
                }
                ExecMessage::ExecResponse(resp) => {
                    if let Some(exit_code) = resp.exit_code {
                        return Ok(exit_code);
                    }
                }
                ExecMessage::Close => {
                    return Ok(0);
                }
                _ => {
                    // Ignore other message types
                }
            }
        }
    }

    /// Execute a command interactively with TTY support.
    ///
    /// This connects stdin/stdout/stderr and supports terminal resizing.
    pub async fn exec_interactive(&mut self, cmd: &str, env: Vec<(String, String)>) -> Result<i32> {
        debug!("Connecting to VM via vsock (interactive): {}", self.socket_path.display());

        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(|e| HyprError::Internal(format!("Failed to connect to VM vsock: {}", e)))?;

        // Get terminal size
        let (rows, cols) = terminal_size().unwrap_or((24, 80));

        // Send exec request with TTY
        let request = ExecRequest {
            session_id: self.session_id,
            command: cmd.to_string(),
            env,
            tty: true,
            rows,
            cols,
        };

        let msg = ExecMessage::ExecRequest(request);
        send_message(&mut stream, &msg).await?;

        // Split the stream for bidirectional I/O
        let (mut reader, mut writer) = stream.into_split();

        // Spawn task to forward stdin to VM
        let stdin_task = tokio::spawn(async move {
            let mut stdin = tokio::io::stdin();
            let mut buf = vec![0u8; 1024];

            loop {
                match stdin.read(&mut buf).await {
                    Ok(0) => break, // EOF
                    Ok(n) => {
                        let msg = ExecMessage::Stdin(buf[..n].to_vec());
                        if let Err(e) = send_message_to_writer(&mut writer, &msg).await {
                            debug!("Failed to send stdin: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        debug!("Failed to read stdin: {}", e);
                        break;
                    }
                }
            }
        });

        // Read output from VM
        let mut exit_code = 0;
        loop {
            match recv_message_from_reader(&mut reader).await {
                Ok(response) => match response {
                    ExecMessage::Stdout(data) => {
                        let mut stdout = tokio::io::stdout();
                        let _ = stdout.write_all(&data).await;
                        let _ = stdout.flush().await;
                    }
                    ExecMessage::Stderr(data) => {
                        let mut stderr = tokio::io::stderr();
                        let _ = stderr.write_all(&data).await;
                        let _ = stderr.flush().await;
                    }
                    ExecMessage::ExecResponse(resp) => {
                        if let Some(code) = resp.exit_code {
                            exit_code = code;
                            break;
                        }
                    }
                    ExecMessage::Close => {
                        break;
                    }
                    _ => {}
                },
                Err(e) => {
                    debug!("Connection closed: {}", e);
                    break;
                }
            }
        }

        stdin_task.abort();
        Ok(exit_code)
    }
}

/// Send a message over the stream.
async fn send_message(stream: &mut UnixStream, msg: &ExecMessage) -> Result<()> {
    let bytes = msg.encode();

    // Send length prefix (4 bytes, big-endian)
    let len = bytes.len() as u32;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| HyprError::Internal(format!("Failed to send message length: {}", e)))?;

    // Send message body
    stream
        .write_all(&bytes)
        .await
        .map_err(|e| HyprError::Internal(format!("Failed to send message: {}", e)))?;

    Ok(())
}

/// Send a message to a write half.
async fn send_message_to_writer(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    msg: &ExecMessage,
) -> Result<()> {
    let bytes = msg.encode();

    let len = bytes.len() as u32;
    writer
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| HyprError::Internal(format!("Failed to send message length: {}", e)))?;

    writer
        .write_all(&bytes)
        .await
        .map_err(|e| HyprError::Internal(format!("Failed to send message: {}", e)))?;

    Ok(())
}

/// Receive a message from the stream.
async fn recv_message(stream: &mut UnixStream) -> Result<ExecMessage> {
    // Read length prefix
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| HyprError::Internal(format!("Failed to read message length: {}", e)))?;
    let len = u32::from_be_bytes(len_buf) as usize;

    // Read message body
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| HyprError::Internal(format!("Failed to read message: {}", e)))?;

    ExecMessage::decode(&buf)
}

/// Receive a message from a read half.
async fn recv_message_from_reader(
    reader: &mut tokio::net::unix::OwnedReadHalf,
) -> Result<ExecMessage> {
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| HyprError::Internal(format!("Failed to read message length: {}", e)))?;
    let len = u32::from_be_bytes(len_buf) as usize;

    let mut buf = vec![0u8; len];
    reader
        .read_exact(&mut buf)
        .await
        .map_err(|e| HyprError::Internal(format!("Failed to read message: {}", e)))?;

    ExecMessage::decode(&buf)
}

/// Generate a random session ID.
fn rand_session_id() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let seed = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
    (seed & 0xFFFFFFFF) as u32
}

/// Get terminal size.
fn terminal_size() -> Option<(u16, u16)> {
    // Try to get terminal size from environment or ioctl
    #[cfg(unix)]
    {
        use std::mem::MaybeUninit;

        #[repr(C)]
        struct Winsize {
            ws_row: libc::c_ushort,
            ws_col: libc::c_ushort,
            ws_xpixel: libc::c_ushort,
            ws_ypixel: libc::c_ushort,
        }

        let mut ws = MaybeUninit::<Winsize>::uninit();
        let ret = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, ws.as_mut_ptr()) };

        if ret == 0 {
            let ws = unsafe { ws.assume_init() };
            return Some((ws.ws_row, ws.ws_col));
        }
    }

    None
}
