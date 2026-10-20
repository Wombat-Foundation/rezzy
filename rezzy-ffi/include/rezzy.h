/* C ABI for rezzy event hashing. Keep in sync with src/lib.rs. */
#ifndef REZZY_H
#define REZZY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Status codes. */
#define REZZY_OK 0
#define REZZY_ERR 1     /* operation failed; *out holds a UTF-8 message */
#define REZZY_BAD_ARG 2 /* null pointer or non-UTF-8 room version; *out is NULL */

/*
 * On REZZY_OK, writes the event ID ("$" + unpadded base64 reference hash) of
 * the JSON event to *out / *out_len. A top-level "event_id" field is ignored,
 * as it is derived data. On REZZY_ERR, *out holds an error message instead.
 * Free any non-NULL *out with rezzy_free. Output is not NUL-terminated.
 */
int rezzy_event_id(const char *room_version, const uint8_t *event_json,
                   size_t event_len, uint8_t **out, size_t *out_len);

/*
 * REZZY_OK when the event's hashes.sha256 matches its content under the room
 * version; REZZY_ERR (with a message in *out) when it does not.
 */
int rezzy_verify_content_hash(const char *room_version,
                              const uint8_t *event_json, size_t event_len,
                              uint8_t **out, size_t *out_len);

/*
 * Describes every event in a JSONL buffer. On REZZY_OK, *out holds the same
 * JSON report object as `rezzy hash events`, including event records with
 * event_id, claimed_event_id, content_hash_ok, links, and a 1-based "line".
 * A line that cannot be hashed yields an {"error": ...} record and the call
 * still succeeds. REZZY_ERR (message in *out) means no events or invalid UTF-8.
 */
int rezzy_hash_events(const char *room_version, const uint8_t *jsonl,
                      size_t jsonl_len, uint8_t **out, size_t *out_len);

/* Releases a buffer returned through *out. Accepts NULL. */
void rezzy_free(uint8_t *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* REZZY_H */
