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
                &body[..body.len().min(500)]
            ),
        )
    })?;
    Ok(val)
}
