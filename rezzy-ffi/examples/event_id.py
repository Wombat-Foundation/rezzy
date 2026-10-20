"""Compute an event ID through the C ABI with ctypes.

cargo build -p rezzy-ffi
python3 rezzy-ffi/examples/event_id.py 12 event.json
"""

import ctypes
import pathlib
import sys

REZZY_OK = 0


def load(path=None):
    if path is None:
        target = pathlib.Path(__file__).resolve().parents[2] / "target" / "debug"
        path = next(target.glob("librezzy_ffi.*"), None) or target / "rezzy_ffi.dll"
    lib = ctypes.CDLL(str(path))
    for name in ("rezzy_event_id", "rezzy_verify_content_hash"):
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
            f"usage: {sys.argv[0]} <event-id|verify-content-hash> <room-version> <event.json>",
            file=sys.stderr,
        )
        sys.exit(2)
    action, version, path = sys.argv[1:]
    function = {
        "event-id": "rezzy_event_id",
        "verify-content-hash": "rezzy_verify_content_hash",
    }.get(action)
    if function is None:
        print("action must be event-id or verify-content-hash", file=sys.stderr)
        sys.exit(2)
    status, text = call(load(), function, version, pathlib.Path(path).read_bytes())
    print(text if text else "content hash valid")
    sys.exit(0 if status == REZZY_OK else 1)
