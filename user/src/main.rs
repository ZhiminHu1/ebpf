use std::{env, mem::size_of, thread, time::Duration};

use anyhow::{Context, Result, ensure};
use aya::{
    Ebpf,
    maps::RingBuf,
    programs::{UProbe, uprobe::UProbeScope},
};
use common::{ACCEPT, CONNECT, ENTER, EXIT, HANDSHAKE, HandshakeEvent};
use common::{Event, MAX_DATA, READ, WRITE};

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    ensure!(
        args.len() == 3,
        "用法: {} <eBPF目标文件> <libssl绝对路径>",
        args[0]
    );
    let mut bpf = Ebpf::load_file(&args[1]).context("加载 eBPF 文件失败")?;
    let probes = [
        ("ssl_read_enter", "SSL_read"),
        ("ssl_read_exit", "SSL_read"),
        ("ssl_write_enter", "SSL_write"),
        ("ssl_write_exit", "SSL_write"),
        ("ssl_connect_enter", "SSL_connect"),
        ("ssl_connect_exit", "SSL_connect"),
        ("ssl_accept_enter", "SSL_accept"),
        ("ssl_accept_exit", "SSL_accept"),
        ("ssl_handshake_enter", "SSL_do_handshake"),
        ("ssl_handshake_exit", "SSL_do_handshake"),
    ];
    for (program_name, symbol) in probes {
        let program: &mut UProbe = bpf
            .program_mut(program_name)
            .with_context(|| format!("找不到程序 {program_name}"))?
            .try_into()?;
        program
            .load()
            .with_context(|| format!("内核加载 {program_name} 失败"))?;
        program
            .attach(symbol, &args[2], UProbeScope::AllProcesses)
            .with_context(|| format!("挂载 {program_name} 到 {symbol} 失败"))?;
    }
    let mut events = RingBuf::try_from(bpf.take_map("EVENTS").context("找不到 EVENTS map")?)?;
    let mut handshakes = RingBuf::try_from(
        bpf.take_map("HANDSHAKES")
            .context("找不到 HANDSHAKES map；请重新编译 eBPF")?,
    )?;
    println!(
        "已挂载到 {}，观察所有使用该库的进程，等待 TLS 握手和 SSL_read / SSL_write ...",
        args[2]
    );
    // bpf 保持存活，拥有探针链接；Ctrl-C 退出后内核释放这些链接。
    loop {
        while let Some(record) = handshakes.next() {
            let Some(event) = decode_handshake(&record) else {
                continue;
            };
            let function = match event.function {
                CONNECT => "SSL_connect",
                ACCEPT => "SSL_accept",
                HANDSHAKE => "SSL_do_handshake",
                _ => continue,
            };
            let phase = if event.phase == ENTER {
                "ENTER"
            } else {
                "EXIT"
            };
            let status = if event.phase == ENTER {
                "started"
            } else if event.result == 1 {
                "completed"
            } else {
                "not_completed (retry or error)"
            };
            println!(
                "ts={} pid={} tid={} uid={} ssl=0x{:x} {} {} ret={} duration={}us status={}",
                event.timestamp_ns,
                event.pid,
                event.tid,
                event.uid,
                event.ssl,
                function,
                phase,
                event.result,
                event.duration_ns / 1000,
                status
            );
        }
        while let Some(record) = events.next() {
            let Some(event) = decode_event(&record) else {
                continue;
            };
            let direction = match event.direction {
                READ => "READ",
                WRITE => "WRITE",
                _ => "UNKNOWN",
            };
            let text = String::from_utf8_lossy(&event.data[..event.captured_len as usize]);
            // 转义终端控制字符，便于安全显示任意应用数据。
            println!(
                "pid={} tid={} uid={} {} actual={} captured={} duration={}us data=\"{}\"",
                event.pid,
                event.tid,
                event.uid,
                direction,
                event.actual_len,
                event.captured_len,
                event.duration_ns / 1000,
                text.escape_debug()
            );
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn decode_handshake(record: &[u8]) -> Option<HandshakeEvent> {
    if record.len() != size_of::<HandshakeEvent>() {
        return None;
    }
    // SAFETY: 长度已校验；结构仅含整数，任意位模式有效，无需地址对齐。
    let event = unsafe { record.as_ptr().cast::<HandshakeEvent>().read_unaligned() };
    if event.function > HANDSHAKE || event.phase > EXIT {
        return None;
    }
    Some(event)
}

fn decode_event(record: &[u8]) -> Option<Event> {
    if record.len() != size_of::<Event>() {
        return None;
    }
    // SAFETY: 已验证长度；Event 仅含整数和字节数组，任意位模式有效。
    // ring buffer 的地址无需满足 Event 对齐要求。
    let event = unsafe { record.as_ptr().cast::<Event>().read_unaligned() };
    if event.captured_len as usize > MAX_DATA || event.captured_len > event.actual_len {
        return None;
    }
    Some(event)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_wire_preserves_negative_return_and_checks_tags() {
        let mut bytes = [0_u8; 48];
        bytes[40..44].copy_from_slice(&(-1_i32).to_ne_bytes());
        bytes[44..48].copy_from_slice(&EXIT.to_ne_bytes());
        assert_eq!(decode_handshake(&bytes).unwrap().result, -1);
        assert!(decode_handshake(&bytes[..47]).is_none());
        bytes[36..40].copy_from_slice(&3_u32.to_ne_bytes());
        assert!(decode_handshake(&bytes).is_none());
    }

    #[test]
    fn decode_checks_wire_length_and_capture_bounds() {
        // Event 的实际线格式：40 字节头部 + 256 字节数据。
        let mut bytes = [0_u8; 296];
        bytes[32..36].copy_from_slice(&3_u32.to_ne_bytes());
        bytes[36..40].copy_from_slice(&3_u32.to_ne_bytes());
        bytes[40..43].copy_from_slice(b"TLS");
        let event = decode_event(&bytes).unwrap();
        assert_eq!(&event.data[..3], b"TLS");
        assert!(decode_event(&bytes[..295]).is_none());
        bytes[36..40].copy_from_slice(&4_u32.to_ne_bytes());
        assert!(decode_event(&bytes).is_none());
        bytes[32..36].copy_from_slice(&257_u32.to_ne_bytes());
        bytes[36..40].copy_from_slice(&257_u32.to_ne_bytes());
        assert!(decode_event(&bytes).is_none());
    }
}
