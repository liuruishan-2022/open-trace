# open-trace

Minimal Aya + Rust eBPF tracepoint experiment copied from the `sword` project structure.

It only loads one tracepoint program:

```text
syscalls:sys_enter_open
```

## Build

```bash
cargo build --release
```

## Run

```bash
RUST_LOG=info cargo run --release
```

The program waits for Ctrl-C after the tracepoint is loaded and attached.
