# rezzy FFI

`rezzy-ffi` exposes event ID calculation and content-hash verification through
a small C ABI. The C declarations are in [`include/rezzy.h`](include/rezzy.h).
`rezzy_hash_events` takes a whole JSONL buffer and returns one JSON record per
line, the same fields as `rezzy hash events`, in one call.
Returned messages and IDs are UTF-8 byte buffers owned by the library; release
them with `rezzy_free`.

Build the shared and static libraries from the repository root:

```sh
cargo build -p rezzy-ffi
```

The Go example uses cgo and links the debug shared library. From the repository
root, run:

```sh
cd rezzy-ffi/examples/go
go run . event-id 12 event.json
go run . verify-content-hash 12 event.json
```

Python uses `ctypes` and loads the built library automatically:

```sh
python3 rezzy-ffi/examples/event_id.py event-id 12 event.json
python3 rezzy-ffi/examples/event_id.py verify-content-hash 12 event.json
```

Both examples require a built `librezzy_ffi` in the workspace's `target/debug`
directory. The Go example also requires Go with cgo enabled and a C toolchain.
