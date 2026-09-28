# 架构与事件流

`common` 是 no_std 共享库，定义无隐式填充的 296 字节 `Event`。
另定义 48 字节 `HandshakeEvent`，保留握手入口/返回阶段、函数编号、SSL 地址和有符号返回值。
`ebpf` 编译为 BPF ELF；`user` 在主机运行，通过 Aya 加载并持有探针链接，
读取 ring buffer 后校验事件长度和捕获边界，再转义输出。

```mermaid
flowchart TD
    User["user：指定 libssl 路径，监听所有进程"] -->|有权限时加载与挂载| Probe["ebpf：十个 OpenSSL 探针"]
    HS["SSL_connect / SSL_accept / SSL_do_handshake"] -->|入口保存，返回查找并删除| HSState["HANDSHAKE_CALLS：线程及函数键，SSL 地址、时间"]
    HSState -->|入口或返回事件| HSRing["HANDSHAKES：1 MiB ring buffer"]
    HSRing -->|用户态校验与输出| Output
    HSRing -->|缓冲区满| Drop
    SSL["使用该库的进程 SSL_read / SSL_write"] -->|入口| State["READ_CALLS / WRITE_CALLS：线程键、指针、长度、时间"]
    SSL -->|返回| Exit["返回探针查找状态并清理"]
    State --> Exit
    Exit -->|成功返回且用户缓冲区可读| Event["common::Event：最多 256 字节明文"]
    Exit -->|无状态、失败或读取错误| Drop["丢弃本次事件"]
    Event -->|输出| Ring["EVENTS：1 MiB ring buffer"]
    Ring -->|缓冲区满| Drop
    Ring -->|用户态校验与转义| Output["终端"]
```

探针在内核执行，只通过受保护 helper 读取目标进程地址。
握手探针仅保存 SSL 地址，不解引用 OpenSSL 内部结构。握手与明文事件独立消费，
应使用时间戳分析先后；握手返回 1 表示完成，其他值可能为重试或错误。
状态插入失败将使返回探针找不到对应记录；正常返回和失败返回均先移除已有状态。
退出观察器后内核释放未固定的程序、map 和链接。当前实现不持久化事件。
