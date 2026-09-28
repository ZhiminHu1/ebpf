# OpenSSL 明文观察实验

使用 Aya 0.14 / aya-ebpf 0.2.1，在指定 OpenSSL 库的 `SSL_read` / `SSL_write`
入口记录参数，返回时读取成功传输的明文并通过 ring buffer 输出。
监听所有使用该库文件的 Linux 进程，每条事件包含 PID。
另挂载 `SSL_connect`、`SSL_accept`、`SSL_do_handshake` 的入口与返回，
通过独立 ring buffer 输出时间戳、SSL 对象地址、原始返回值与调用耗时。
返回 1 表示握手完成；其他值可能需要重试或发生错误，不能仅凭返回值分类。
入口事件的 ret=0 是占位值，不是函数返回值。

## 构建（x86_64 Linux）

需要已安装的 `bpf-linker`、nightly Rust 和 rust-src：

```bash
rustup toolchain install nightly --component rust-src
bpf-linker --version
RUSTFLAGS='--cfg bpf_target_arch="x86_64" -C linker=bpf-linker' \
cargo +nightly build -p ebpf --release --target bpfel-unknown-none -Z build-std=core
cargo build -p user --release
```

两个目标必须分别编译：`ebpf` 使用 BPF 指令集，`user` 使用主机指令集。
默认 `cargo build` 只构建用户态。

## 运行

在 Ubuntu x86_64 上先启动观察器，无需传入 PID：

```bash
TLS_LIBSSL=/usr/lib/x86_64-linux-gnu/libssl.so.3
test -n "$TLS_LIBSSL" && sudo ./target/release/user \
    ./target/bpfel-unknown-none/release/ebpf "$TLS_LIBSSL"
```

库路径需对应被观察程序实际使用的文件。看到“已挂载”后，在另一终端执行：

```bash
curl -V
curl --http1.1 https://example.com
```

检查 `curl -V` 输出是否使用 OpenSSL；Ctrl-C 退出观察器。
需要 root 或合适的 BPF/perf 权限。加载失败的错误链包含内核或 Aya 返回的原因。

示意输出（不是本机实测）：

```text
pid=12345 tid=12345 uid=1000 WRITE actual=3 captured=3 duration=12us data="TLS"
```

## 验证和限制

```bash
cargo fmt --all -- --check
cargo test -p user
cargo clippy -p user -p common -- -D warnings
```

- 每次最多捕获 256 字节；耗时是 SSL 函数调用总耗时，不是纯密码算法耗时。
- 明文只挂载 `SSL_read` / `SSL_write`；`SSL_*_ex` 和 rustls 不在当前范围内。
- 握手事件是函数调用信息，不包含 ClientHello/ServerHello 消息、证书、协商参数或密钥。
- 握手函数可能嵌套或多次重试；按 PID、SSL 地址及时间戳关联，不应按事件数量统计连接。
- 两个 ring buffer 独立消费，终端显示顺序不保证全局时间顺序。
- 仅覆盖使用指定库文件的进程；其他库文件及静态链接的 TLS 不在范围内。
- 缓冲区读取失败、状态表或 ring buffer 满时会丢事件，目前不统计丢失数量。
- 每线程每方向保存一条在途调用，不支持同方向递归/信号重入。
- 握手状态按线程和函数保存，不支持同一函数递归/信号重入，也不能关联跨线程返回。
- 记录不是完整 HTTP 消息，也没有连接重组；输出会转义控制字符。
- 当前只完成编译及用户态检查，需在有权限的环境验证内核 verifier 和实际 TLS 事件。

[架构与事件流](docs/architecture/README.md)
