//! Protocol definitions for exec communication over vsock.
//!
//! # Wire Format
//!
//! All messages are length-prefixed:
//!
//! ```text
//! ┌─────────────────┬──────────────────────────────┐
//! │ Length (4 bytes)│ Message Body (variable)      │
//! │ big-endian      │                              │
//! └─────────────────┴──────────────────────────────┘
//! ```
//!
//! # Message Body Format
//!
//! ```text
//! ┌──────────┬─────────────┬─────────────────────┐
//! │ Type (1) │ Session (4) │ Payload (variable)  │
//! └──────────┴─────────────┴─────────────────────┘
//! ```

use crate::error::{HyprError, Result};

/// Message types for exec protocol.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// Execute request from host to guest.
    ExecRequest = 0x01,
    /// Execute response from guest to host (includes PID, exit code).
    ExecResponse = 0x02,
    /// Stdin data from host to guest.
    Stdin = 0x03,
    /// Stdout data from guest to host.
    Stdout = 0x04,
    /// Stderr data from guest to host.
    Stderr = 0x05,
    /// Signal request (host to guest).
    Signal = 0x06,
    /// Terminal resize (host to guest).
    Resize = 0x07,
    /// Close session.
    Close = 0x08,
}

impl TryFrom<u8> for MessageType {
    type Error = HyprError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(MessageType::ExecRequest),
            0x02 => Ok(MessageType::ExecResponse),
            0x03 => Ok(MessageType::Stdin),
            0x04 => Ok(MessageType::Stdout),
            0x05 => Ok(MessageType::Stderr),
            0x06 => Ok(MessageType::Signal),
            0x07 => Ok(MessageType::Resize),
            0x08 => Ok(MessageType::Close),
            _ => Err(HyprError::Internal(format!("Unknown message type: {}", value))),
        }
    }
}

/// Request to execute a command.
#[derive(Debug, Clone)]
pub struct ExecRequest {
    /// Session ID for this execution.
    pub session_id: u32,
    /// Command to execute (passed to /bin/sh -c).
    pub command: String,
    /// Environment variables.
    pub env: Vec<(String, String)>,
    /// Allocate a PTY for this execution.
    pub tty: bool,
    /// Terminal rows (if tty=true).
    pub rows: u16,
    /// Terminal columns (if tty=true).
    pub cols: u16,
}

/// Response to an exec request.
#[derive(Debug, Clone)]
pub struct ExecResponse {
    /// Session ID.
    pub session_id: u32,
    /// Process ID in guest (if started).
    pub pid: Option<u32>,
    /// Exit code (if completed).
    pub exit_code: Option<i32>,
}

/// All message types.
#[derive(Debug, Clone)]
pub enum ExecMessage {
    ExecRequest(ExecRequest),
    ExecResponse(ExecResponse),
    Stdin(Vec<u8>),
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Signal { session_id: u32, signal: u8 },
    Resize { session_id: u32, rows: u16, cols: u16 },
    Close,
}

impl ExecMessage {
    /// Encode the message to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();

        match self {
            ExecMessage::ExecRequest(req) => {
                buf.push(MessageType::ExecRequest as u8);
                buf.extend_from_slice(&req.session_id.to_be_bytes());

                // Flags: bit 0 = tty
                let flags = if req.tty { 1u8 } else { 0u8 };
                buf.push(flags);

                // Terminal size
                buf.extend_from_slice(&req.rows.to_be_bytes());
                buf.extend_from_slice(&req.cols.to_be_bytes());

                // Command length + command
                let cmd_bytes = req.command.as_bytes();
                buf.extend_from_slice(&(cmd_bytes.len() as u32).to_be_bytes());
                buf.extend_from_slice(cmd_bytes);

                // Env count + env vars
                buf.extend_from_slice(&(req.env.len() as u32).to_be_bytes());
                for (key, value) in &req.env {
                    let key_bytes = key.as_bytes();
                    let value_bytes = value.as_bytes();
                    buf.extend_from_slice(&(key_bytes.len() as u16).to_be_bytes());
                    buf.extend_from_slice(key_bytes);
                    buf.extend_from_slice(&(value_bytes.len() as u16).to_be_bytes());
                    buf.extend_from_slice(value_bytes);
                }
            }

            ExecMessage::ExecResponse(resp) => {
                buf.push(MessageType::ExecResponse as u8);
                buf.extend_from_slice(&resp.session_id.to_be_bytes());

                // Flags: bit 0 = has_pid, bit 1 = has_exit_code
                let mut flags = 0u8;
                if resp.pid.is_some() {
                    flags |= 1;
                }
                if resp.exit_code.is_some() {
                    flags |= 2;
                }
                buf.push(flags);

                if let Some(pid) = resp.pid {
                    buf.extend_from_slice(&pid.to_be_bytes());
                }
                if let Some(exit_code) = resp.exit_code {
                    buf.extend_from_slice(&exit_code.to_be_bytes());
                }
            }

            ExecMessage::Stdin(data) => {
                buf.push(MessageType::Stdin as u8);
                buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
                buf.extend_from_slice(data);
            }

            ExecMessage::Stdout(data) => {
                buf.push(MessageType::Stdout as u8);
                buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
                buf.extend_from_slice(data);
            }

            ExecMessage::Stderr(data) => {
                buf.push(MessageType::Stderr as u8);
                buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
                buf.extend_from_slice(data);
            }

            ExecMessage::Signal { session_id, signal } => {
                buf.push(MessageType::Signal as u8);
                buf.extend_from_slice(&session_id.to_be_bytes());
                buf.push(*signal);
            }

            ExecMessage::Resize { session_id, rows, cols } => {
                buf.push(MessageType::Resize as u8);
                buf.extend_from_slice(&session_id.to_be_bytes());
                buf.extend_from_slice(&rows.to_be_bytes());
                buf.extend_from_slice(&cols.to_be_bytes());
            }

            ExecMessage::Close => {
                buf.push(MessageType::Close as u8);
            }
        }

        buf
    }

    /// Decode a message from bytes.
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(HyprError::Internal("Empty message".to_string()));
        }

        let msg_type = MessageType::try_from(data[0])?;
        let payload = &data[1..];

        match msg_type {
            MessageType::ExecRequest => {
                if payload.len() < 9 {
                    return Err(HyprError::Internal("ExecRequest too short".to_string()));
                }

                let session_id =
                    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let flags = payload[4];
                let tty = (flags & 1) != 0;
                let rows = u16::from_be_bytes([payload[5], payload[6]]);
                let cols = u16::from_be_bytes([payload[7], payload[8]]);

                let cmd_len =
                    u32::from_be_bytes([payload[9], payload[10], payload[11], payload[12]])
                        as usize;
                let cmd_start = 13;
                let cmd_end = cmd_start + cmd_len;

                if payload.len() < cmd_end {
                    return Err(HyprError::Internal("ExecRequest command truncated".to_string()));
                }

                let command = String::from_utf8_lossy(&payload[cmd_start..cmd_end]).to_string();

                // Parse env vars
                let env_start = cmd_end;
                let mut env = Vec::new();

                if payload.len() > env_start + 4 {
                    let env_count = u32::from_be_bytes([
                        payload[env_start],
                        payload[env_start + 1],
                        payload[env_start + 2],
                        payload[env_start + 3],
                    ]) as usize;

                    let mut offset = env_start + 4;
                    for _ in 0..env_count {
                        if offset + 2 > payload.len() {
                            break;
                        }
                        let key_len =
                            u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
                        offset += 2;

                        if offset + key_len > payload.len() {
                            break;
                        }
                        let key =
                            String::from_utf8_lossy(&payload[offset..offset + key_len]).to_string();
                        offset += key_len;

                        if offset + 2 > payload.len() {
                            break;
                        }
                        let value_len =
                            u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
                        offset += 2;

                        if offset + value_len > payload.len() {
                            break;
                        }
                        let value = String::from_utf8_lossy(&payload[offset..offset + value_len])
                            .to_string();
                        offset += value_len;

                        env.push((key, value));
                    }
                }

                Ok(ExecMessage::ExecRequest(ExecRequest {
                    session_id,
                    command,
                    env,
                    tty,
                    rows,
                    cols,
                }))
            }

            MessageType::ExecResponse => {
                if payload.len() < 5 {
                    return Err(HyprError::Internal("ExecResponse too short".to_string()));
                }

                let session_id =
                    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let flags = payload[4];
                let has_pid = (flags & 1) != 0;
                let has_exit_code = (flags & 2) != 0;

                let mut offset = 5;
                let pid = if has_pid && offset + 4 <= payload.len() {
                    let pid = u32::from_be_bytes([
                        payload[offset],
                        payload[offset + 1],
                        payload[offset + 2],
                        payload[offset + 3],
                    ]);
                    offset += 4;
                    Some(pid)
                } else {
                    None
                };

                let exit_code = if has_exit_code && offset + 4 <= payload.len() {
                    let code = i32::from_be_bytes([
                        payload[offset],
                        payload[offset + 1],
                        payload[offset + 2],
                        payload[offset + 3],
                    ]);
                    Some(code)
                } else {
                    None
                };

                Ok(ExecMessage::ExecResponse(ExecResponse { session_id, pid, exit_code }))
            }

            MessageType::Stdin | MessageType::Stdout | MessageType::Stderr => {
                if payload.len() < 4 {
                    return Err(HyprError::Internal("Data message too short".to_string()));
                }

                let data_len =
                    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
                let data = payload.get(4..4 + data_len).unwrap_or(&[]).to_vec();

                match msg_type {
                    MessageType::Stdin => Ok(ExecMessage::Stdin(data)),
                    MessageType::Stdout => Ok(ExecMessage::Stdout(data)),
                    MessageType::Stderr => Ok(ExecMessage::Stderr(data)),
                    _ => unreachable!(),
                }
            }

            MessageType::Signal => {
                if payload.len() < 5 {
                    return Err(HyprError::Internal("Signal message too short".to_string()));
                }

                let session_id =
                    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let signal = payload[4];

                Ok(ExecMessage::Signal { session_id, signal })
            }

            MessageType::Resize => {
                if payload.len() < 8 {
                    return Err(HyprError::Internal("Resize message too short".to_string()));
                }

                let session_id =
                    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                let rows = u16::from_be_bytes([payload[4], payload[5]]);
                let cols = u16::from_be_bytes([payload[6], payload[7]]);

                Ok(ExecMessage::Resize { session_id, rows, cols })
            }

            MessageType::Close => Ok(ExecMessage::Close),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exec_request_roundtrip() {
        let req = ExecRequest {
            session_id: 12345,
            command: "/bin/ls -la".to_string(),
            env: vec![("PATH".to_string(), "/usr/bin".to_string())],
            tty: true,
            rows: 24,
            cols: 80,
        };

        let msg = ExecMessage::ExecRequest(req);
        let encoded = msg.encode();
        let decoded = ExecMessage::decode(&encoded).unwrap();

        if let ExecMessage::ExecRequest(decoded_req) = decoded {
            assert_eq!(decoded_req.session_id, 12345);
            assert_eq!(decoded_req.command, "/bin/ls -la");
            assert!(decoded_req.tty);
            assert_eq!(decoded_req.rows, 24);
            assert_eq!(decoded_req.cols, 80);
            assert_eq!(decoded_req.env.len(), 1);
            assert_eq!(decoded_req.env[0], ("PATH".to_string(), "/usr/bin".to_string()));
        } else {
            panic!("Expected ExecRequest");
        }
    }

    #[test]
    fn test_exec_response_roundtrip() {
        let resp = ExecResponse { session_id: 12345, pid: Some(999), exit_code: Some(0) };

        let msg = ExecMessage::ExecResponse(resp);
        let encoded = msg.encode();
        let decoded = ExecMessage::decode(&encoded).unwrap();

        if let ExecMessage::ExecResponse(decoded_resp) = decoded {
            assert_eq!(decoded_resp.session_id, 12345);
            assert_eq!(decoded_resp.pid, Some(999));
            assert_eq!(decoded_resp.exit_code, Some(0));
        } else {
            panic!("Expected ExecResponse");
        }
    }

    #[test]
    fn test_stdout_roundtrip() {
        let data = b"Hello, World!".to_vec();
        let msg = ExecMessage::Stdout(data.clone());
        let encoded = msg.encode();
        let decoded = ExecMessage::decode(&encoded).unwrap();

        if let ExecMessage::Stdout(decoded_data) = decoded {
            assert_eq!(decoded_data, data);
        } else {
            panic!("Expected Stdout");
        }
    }
}
