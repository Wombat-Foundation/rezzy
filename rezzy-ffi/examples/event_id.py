"""Compute an event ID through the C ABI with ctypes.

cargo build -p rezzy-ffi
python3 rezzy-ffi/examples/event_id.py event-id 12 event.json
"""

import ctypes
import pathlib
import sys

REZZY_OK = 0


def load(path=None):
    """Load the FFI library and configure its ctypes signatures.

    With no path, look in target/debug for the platform library. Raise
    SystemExit if loading fails; missing exported symbols raise AttributeError.
    """
    if path is None:
        target = pathlib.Path(__file__).resolve().parents[2] / "target" / "debug"
        names = {
            "win32": ("rezzy_ffi.dll",),
            "darwin": ("librezzy_ffi.dylib",),
        }.get(sys.platform, ("librezzy_ffi.so",))
        path = next(
            (target / name for name in names if (target / name).exists()),
            target / "rezzy_ffi.dll",
        )
    try:
        lib = ctypes.CDLL(str(path))
    except OSError as error:
        raise SystemExit(
            f"could not load {path}; build the library with `cargo build -p rezzy-ffi`: {error}"
        ) from error
    for name in ("rezzy_event_id", "rezzy_verify_content_hash", "rezzy_hash_events"):
        fn = getattr(lib, name)
        fn.argtypes = [
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)),
            ctypes.POINTER(ctypes.c_size_t),
        ]
        fn.restype = ctypes.c_int
    lib.rezzy_free.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]
    lib.rezzy_free.restype = None
    return lib


def call(lib, name, room_version, event: bytes):
    """Call a configured hashing symbol and return its status and decoded output.

    Pass JSON bytes for a single-event operation or JSONL for rezzy_hash_events.
    Operation errors are returned as statuses and messages. UTF-8 decoding
    errors raise UnicodeDecodeError; successfully decoded buffers are freed.
    """
    out = ctypes.POINTER(ctypes.c_uint8)()
    out_len = ctypes.c_size_t()
    status = getattr(lib, name)(
        room_version.encode(),
        event,
        len(event),
        ctypes.byref(out),
        ctypes.byref(out_len),
    )
    text = ctypes.string_at(out, out_len.value).decode() if out else ""
    lib.rezzy_free(out, out_len)
    return status, text


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(
            f"usage: {sys.argv[0]} <event-id|verify-content-hash|hash-events> <room-version> <event.jsonl>",
            file=sys.stderr,
        )
        sys.exit(2)
    action, version, path = sys.argv[1:]
    function = {
        "event-id": "rezzy_event_id",
        "verify-content-hash": "rezzy_verify_content_hash",
        "hash-events": "rezzy_hash_events",
    }.get(action)
    if function is None:
        print(
            "action must be event-id, verify-content-hash, or hash-events",
            file=sys.stderr,
        )
        sys.exit(2)
    status, text = call(load(), function, version, pathlib.Path(path).read_bytes())
    if status == REZZY_OK:
        print(text if text else "content hash valid")
        sys.exit(0)
    print(text or f"rezzy failed with status {status}", file=sys.stderr)
    sys.exit(1)
