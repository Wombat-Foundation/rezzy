// Copyright 2026 Shane Jaroch
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/// A response-body preview of at most `max_bytes`, never splitting a UTF-8
/// character.
///
/// Indexing a `str` at a non-char-boundary panics, and a remote server controls
/// the response bytes, so the window is walked back to the nearest boundary.
fn body_preview(body: &str, max_bytes: usize) -> &str {
    let mut end = body.len().min(max_bytes);
    while !body.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    &body[..end]
}

/// Fetch the room state over the network.
///
/// # Errors
///
/// Returns an error when the request fails, the server returns a non-success
/// status, or the response body is not valid JSON.
pub fn fetch_room_state(
    homeserver: &str,
    room_id: &str,
    token: Option<&str>,
) -> Result<rezzy::JsonValue, crate::error::AppError> {
    let base = if homeserver.starts_with("http://") || homeserver.starts_with("https://") {
        homeserver.to_string()
    } else {
        format!("https://{homeserver}")
    };
    let url = format!("{base}/_matrix/client/v3/rooms/{room_id}/state");
    #[cfg(not(feature = "tls"))]
    if url.starts_with("https://") {
        bail_code!(
            crate::error::ErrorCode::NetworkError,
            "HTTPS request requires the `tls` feature; rebuild rezzy-cli with `--features tls` or use http://"
        );
    }
    eprintln!("Fetching {url}");
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    let mut request = agent.get(&url).header("User-Agent", crate::USER_AGENT);
    if let Some(t) = token {
        request = request.header("Authorization", format!("Bearer {t}"));
    }

    let mut response = match request.call() {
        Ok(resp) => resp,
        Err(e) => bail_code!(crate::error::ErrorCode::NetworkError, "Request failed: {e}"),
    };
    let code = response.status().as_u16();
    let body = response.body_mut().read_to_string().map_err(|e| {
        crate::error::AppError::new(crate::error::ErrorCode::NetworkError, e.to_string())
    })?;
    if code >= 400 {
        bail_code!(crate::error::ErrorCode::NetworkError, "HTTP {code}: {body}");
    }

    let val: rezzy::JsonValue = rezzy::JsonValue::parse(&body).map_err(|e| {
        crate::error::AppError::new(
            crate::error::ErrorCode::NetworkError,
            format!(
                "Failed to parse JSON: {}. Response: {}",
                e,
                body_preview(&body, 500)
            ),
        )
    })?;
    Ok(val)
}

#[cfg(test)]
mod tests {
    use super::body_preview;

    #[test]
    fn preview_walks_back_off_a_multi_byte_char() {
        // "aé" is 3 bytes; 200 of them is 600 bytes, and offset 500 lands on
        // the second byte of a two-byte `é`. The unguarded slice panicked here.
        let body = "aé".repeat(200);
        assert_eq!(body.len(), 600);
        assert!(!body.is_char_boundary(500));
        let preview = body_preview(&body, 500);
        assert_eq!(preview.len(), 499);
        assert!(preview.is_char_boundary(preview.len()));
    }

    #[test]
    fn preview_truncates_on_char_boundary() {
        let body = "aé".repeat(200); // 600 bytes
        assert!(body.len() > 500);
        let preview = body_preview(&body, 500);
        assert!(preview.len() <= 500);
        assert!(preview.is_char_boundary(preview.len()));
        assert!(body.starts_with(preview));
    }

    #[test]
    fn preview_handles_short_and_empty() {
        assert_eq!(body_preview("", 500), "");
        assert_eq!(body_preview("abc", 500), "abc");
        assert_eq!(body_preview("abc", 2), "ab");
    }

    #[test]
    fn preview_walks_back_off_a_three_byte_char_at_the_limit() {
        // 3-byte chars put boundaries at multiples of 3, so byte 500 sits
        // inside the character spanning [498, 501).
        let body = "€".repeat(400); // 1200 bytes
        assert_eq!(body.len(), 1200);
        assert!(!body.is_char_boundary(500));
        let preview = body_preview(&body, 500);
        assert_eq!(preview.len(), 498);
        assert!(preview.is_char_boundary(preview.len()));
        assert!(body.starts_with(preview));
    }

    #[test]
    fn preview_never_panics_on_any_boundary() {
        // Every possible max that could land inside the multi-byte run.
        let body = "€".repeat(100); // 3-byte chars
        for max in 0..=300 {
            let preview = body_preview(&body, max);
            assert!(preview.is_char_boundary(preview.len()));
            assert!(preview.len() <= max);
        }
    }
}
