//! WebSocket Message Size Limiting Plugin
//!
//! Enforces per-proxy frame and reassembled-message limits on WebSocket
//! connections. The shared relay installs these limits in both tungstenite
//! parsers before reads, so declared oversized frames are rejected before
//! payload reservation and fragmented messages have an independent bound.
//!
//! This is the WebSocket equivalent of `request_size_limiting` for HTTP.
//! `requires_ws_frame_hooks()` keeps tunnel mode disabled; enforcement itself
//! is parser-level because `on_ws_frame` receives reassembled messages.
//!
//! Config:
//! ```json
//! {
//!   "max_frame_bytes": 65536,
//!   "max_message_bytes": 262144,
//!   "close_reason": "Message too large"
//! }
//! ```

use serde_json::Value;
use std::sync::Arc;
use tracing::warn;

use super::utils::size_limit::required_positive_usize;
use super::{Plugin, ProxyProtocol, WS_ONLY_PROTOCOLS, WebSocketSizeLimits};

pub struct WsMessageSizeLimiting {
    max_frame_bytes: usize,
    max_message_bytes: usize,
    close_reason: Arc<str>,
}

impl WsMessageSizeLimiting {
    const MAX_CLOSE_REASON_BYTES: usize = 123;

    pub fn new(config: &Value) -> Result<Self, String> {
        if !config.is_object() {
            return Err("ws_message_size_limiting: config must be an object".to_string());
        }

        let max_frame_bytes =
            required_positive_usize(config, "max_frame_bytes", "ws_message_size_limiting")?;
        let max_message_bytes = match config.get("max_message_bytes") {
            Some(_) => required_positive_usize(
                config,
                "max_message_bytes",
                "ws_message_size_limiting",
            )?,
            None => max_frame_bytes.saturating_mul(4),
        };
        if max_message_bytes < max_frame_bytes {
            return Err(
                "ws_message_size_limiting: 'max_message_bytes' must be greater than or equal to 'max_frame_bytes'"
                    .to_string(),
            );
        }

        let mut close_reason = optional_string(config, "close_reason")?
            .unwrap_or("Message too large")
            .to_string();
        if close_reason.len() > Self::MAX_CLOSE_REASON_BYTES {
            warn!(
                max_bytes = Self::MAX_CLOSE_REASON_BYTES,
                "ws_message_size_limiting: 'close_reason' exceeds WebSocket limit — truncating"
            );
            close_reason.truncate(Self::truncate_utf8_boundary(
                &close_reason,
                Self::MAX_CLOSE_REASON_BYTES,
            ));
        }

        Ok(Self {
            max_frame_bytes,
            max_message_bytes,
            close_reason: Arc::from(close_reason),
        })
    }

    fn truncate_utf8_boundary(value: &str, max_bytes: usize) -> usize {
        let mut end = value.len().min(max_bytes);
        while end > 0 && !value.is_char_boundary(end) {
            end -= 1;
        }
        end
    }
}

fn optional_string<'a>(config: &'a Value, field: &'static str) -> Result<Option<&'a str>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_str()
        .map(Some)
        .ok_or_else(|| format!("ws_message_size_limiting: '{field}' must be a string"))
}

impl Plugin for WsMessageSizeLimiting {
    fn name(&self) -> &str {
        "ws_message_size_limiting"
    }

    fn priority(&self) -> u16 {
        super::priority::WS_MESSAGE_SIZE_LIMITING
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        WS_ONLY_PROTOCOLS
    }

    fn requires_ws_frame_hooks(&self) -> bool {
        true
    }

    fn websocket_size_limits(&self) -> Option<WebSocketSizeLimits> {
        Some(WebSocketSizeLimits {
            max_frame_bytes: self.max_frame_bytes,
            max_message_bytes: self.max_message_bytes,
            close_reason: Arc::clone(&self.close_reason),
        })
    }
}
