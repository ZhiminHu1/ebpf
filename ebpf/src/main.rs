#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_probe_read_user_buf,
        generated::bpf_ktime_get_ns,
    },
    macros::{map, uprobe, uretprobe},
    maps::{HashMap, RingBuf},
    programs::{ProbeContext, RetProbeContext},
};
use common::{ACCEPT, CONNECT, ENTER, EXIT, HANDSHAKE, HandshakeEvent};
use common::{Event, MAX_DATA, READ, WRITE};

#[repr(C)]
#[derive(Clone, Copy)]
struct HandshakeCall {
    ssl: u64,
    start_ns: u64,
}

#[map]
static HANDSHAKE_CALLS: HashMap<(u64, u64), HandshakeCall> = HashMap::with_max_entries(4096, 0);

#[map]
static HANDSHAKES: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

#[uprobe]
pub fn ssl_connect_enter(ctx: ProbeContext) -> u32 {
    handshake_enter(ctx, CONNECT)
}
#[uretprobe]
pub fn ssl_connect_exit(ctx: RetProbeContext) -> u32 {
    handshake_exit(ctx, CONNECT)
}
#[uprobe]
pub fn ssl_accept_enter(ctx: ProbeContext) -> u32 {
    handshake_enter(ctx, ACCEPT)
}
#[uretprobe]
pub fn ssl_accept_exit(ctx: RetProbeContext) -> u32 {
    handshake_exit(ctx, ACCEPT)
}
#[uprobe]
pub fn ssl_handshake_enter(ctx: ProbeContext) -> u32 {
    handshake_enter(ctx, HANDSHAKE)
}
#[uretprobe]
pub fn ssl_handshake_exit(ctx: RetProbeContext) -> u32 {
    handshake_exit(ctx, HANDSHAKE)
}

#[inline(always)]
fn handshake_enter(ctx: ProbeContext, function: u32) -> u32 {
    let key = (bpf_get_current_pid_tgid(), function as u64);
    let _ = HANDSHAKE_CALLS.remove(&key);
    let Some(ssl) = ctx.arg::<u64>(0) else {
        return 0;
    };
    // SAFETY: 内核时间 helper 可在 uprobe 上下文调用。
    let now = unsafe { bpf_ktime_get_ns() };
    let call = HandshakeCall { ssl, start_ns: now };
    if HANDSHAKE_CALLS.insert(&key, call, 0).is_ok() {
        emit_handshake(key.0, call, now, function, ENTER, 0);
    }
    0
}

#[inline(always)]
fn handshake_exit(ctx: RetProbeContext, function: u32) -> u32 {
    let key = (bpf_get_current_pid_tgid(), function as u64);
    // SAFETY: 立即复制 map 值，删除时不保留引用。
    let Some(call) = (unsafe { HANDSHAKE_CALLS.get(&key).copied() }) else {
        return 0;
    };
    let _ = HANDSHAKE_CALLS.remove(&key);
    // SAFETY: 内核时间 helper 可在 uretprobe 上下文调用。
    let now = unsafe { bpf_ktime_get_ns() };
    emit_handshake(key.0, call, now, function, EXIT, ctx.ret::<i32>());
    0
}

#[inline(always)]
fn emit_handshake(key: u64, call: HandshakeCall, now: u64, function: u32, phase: u32, result: i32) {
    let event = HandshakeEvent {
        timestamp_ns: now,
        duration_ns: now - call.start_ns,
        ssl: call.ssl,
        pid: (key >> 32) as u32,
        tid: key as u32,
        uid: bpf_get_current_uid_gid() as u32,
        function,
        result,
        phase,
    };
    let _ = HANDSHAKES.output::<HandshakeEvent>(&event, 0);
}
#[repr(C)]
#[derive(Clone, Copy)]
struct Call {
    ptr: u64,
    start_ns: u64,
    requested_len: u32,
    reserved: u32,
}

#[map]
static READ_CALLS: HashMap<u64, Call> = HashMap::with_max_entries(4096, 0);

#[map]
static WRITE_CALLS: HashMap<u64, Call> = HashMap::with_max_entries(4096, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(1 << 20, 0);

#[uprobe]
pub fn ssl_read_enter(ctx: ProbeContext) -> u32 {
    enter(ctx, &READ_CALLS)
}

#[uprobe]
pub fn ssl_write_enter(ctx: ProbeContext) -> u32 {
    enter(ctx, &WRITE_CALLS)
}

#[uretprobe]
pub fn ssl_read_exit(ctx: RetProbeContext) -> u32 {
    exit(ctx, &READ_CALLS, READ)
}

#[uretprobe]
pub fn ssl_write_exit(ctx: RetProbeContext) -> u32 {
    exit(ctx, &WRITE_CALLS, WRITE)
}

#[inline(always)]
fn enter(ctx: ProbeContext, calls: &HashMap<u64, Call>) -> u32 {
    let key = bpf_get_current_pid_tgid();
    // clean
    let _ = calls.remove(&key);
    // ssl second para 'buf'
    let Some(ptr) = ctx.arg::<u64>(1) else {
        return 0;
    };
    // third para 'num' type is 'C int'
    let Some(requested_len) = ctx.arg::<i32>(2) else {
        return 0;
    };
    if ptr == 0 || requested_len <= 0 {
        return 0;
    }
    let call = Call {
        ptr,
        // SAFETY: BPF 上下文中调用内核时间 helper。
        start_ns: unsafe { bpf_ktime_get_ns() },
        requested_len: requested_len as u32,
        reserved: 0,
    };
    let _ = calls.insert(&key, call, 0);
    0
}
#[inline(always)]
fn exit(ctx: RetProbeContext, calls: &HashMap<u64, Call>, direction: u32) -> u32 {
    let key = bpf_get_current_pid_tgid();
    // SAFETY: 按当前线程查找，立即复制；删除前不保留 map 引用。
    let Some(call) = (unsafe { calls.get(&key).copied() }) else {
        return 0;
    };
    let _ = calls.remove(&key);
    let actual_len = ctx.ret::<i32>();

    if actual_len <= 0 {
        return 0;
    }
    let captured_len = (actual_len as usize)
        .min(call.requested_len as usize)
        .min(MAX_DATA);

    if captured_len == 0 {
        return 0;
    }
    // SAFETY: BPF 上下文中调用内核时间 helper。
    let now = unsafe { bpf_ktime_get_ns() };

    let mut event = Event {
        timestamp_ns: now,
        duration_ns: now - call.start_ns,
        pid: (key >> 32) as u32,
        tid: key as u32,
        uid: bpf_get_current_uid_gid() as u32,
        direction,
        actual_len: actual_len as u32,
        captured_len: captured_len as u32,
        data: [0; MAX_DATA],
    };
    // SAFETY: helper 保护用户地址读取；目标切片限制在已初始化数组内。
    let result =
        unsafe { bpf_probe_read_user_buf(call.ptr as *const u8, &mut event.data[..captured_len]) };
    if result.is_err() {
        return 0;
    }

    let _ = EVENTS.output::<Event>(&event, 0);
    0
}
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
pub static LICENSE: [u8; 4] = *b"GPL\0";
