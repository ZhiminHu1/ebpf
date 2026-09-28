#![no_std]

pub const MAX_DATA: usize = 256;

pub const READ: u32 = 0;
pub const WRITE: u32 = 1;

pub const CONNECT: u32 = 0;
pub const ACCEPT: u32 = 1;
pub const HANDSHAKE: u32 = 2;
pub const ENTER: u32 = 0;
pub const EXIT: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct HandshakeEvent {
    pub timestamp_ns: u64,
    pub duration_ns: u64,
    pub ssl: u64,
    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub function: u32,
    pub result: i32,
    pub phase: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Event {
    pub timestamp_ns: u64,
    pub duration_ns: u64,

    pub pid: u32,
    pub tid: u32,
    pub uid: u32,
    pub direction: u32,

    // OpenSSL 实际返回的成功读写长度。
    pub actual_len: u32,

    // 本次事件实际携带的明文长度，最多 256 字节。
    pub captured_len: u32,

    pub data: [u8; MAX_DATA],
}
