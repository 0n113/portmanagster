use tauri::State;
use reqwest::{redirect, Client, Method, Url};
use serde::{Deserialize, Serialize};

/// The only endpoint the UI may reach through `send_tauri_http_request`:
/// the Portmaster core API.
const API_SCHEME: &str = "http";
const API_HOST: &str = "127.0.0.1";
const API_PORT: u16 = 817;

/// Reports whether the URL points to the Portmaster core API.
///
/// Requests are sent by the app binary, which the core trusts. Content in
/// the webview must therefore not be able to choose another destination.
fn is_core_api_url(url: &Url) -> bool {
    url.scheme() == API_SCHEME
        && url.host_str() == Some(API_HOST)
        && is_api_port(url.port_or_known_default())
        && url.username().is_empty()
        && url.password().is_none()
}

fn is_api_port(port: Option<u16>) -> bool {
    // In development the UI is served by `ng serve` on port 4200, which
    // proxies the API (see `may_navigate_to_ui`).
    #[cfg(debug_assertions)]
    if port == Some(4200) {
        return true;
    }
    port == Some(API_PORT)
}

/// Creates and configures a shared HTTP client for application-wide use.
/// 
/// Returns a reqwest Client configured with:
/// - Connection pooling
/// - Persistent cookie store
/// 
/// Client can be accessed from UI through the exposed Tauri command `send_tauri_http_request(...)`
/// Such requests execute directly from the Tauri app binary, not from the WebView process
pub fn create_http_client() -> Client {
    Client::builder()
        // Maximum idle connections per host
        .pool_max_idle_per_host(10)
        // Enable cookie support
        .cookie_store(true)
        // Never follow a redirect away from the core API.
        .redirect(redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 10 {
                attempt.error("too many redirects")
            } else if is_core_api_url(attempt.url()) {
                attempt.follow()
            } else {
                attempt.stop()
            }
        }))
        .user_agent("Portmaster UI")
        .build()
        .expect("failed to build HTTP client")
}

#[derive(Deserialize)]
pub struct HttpRequestOptions {
  method: String,
  headers: Vec<(String, String)>,
  body: Option<Vec<u8>>,
}

#[derive(Serialize)]
pub struct HttpResponse {
  status: u16,
  status_text: String,
  headers: Vec<(String, String)>,
  body: Vec<u8>,
}

#[tauri::command]
pub async fn send_tauri_http_request(
  client: State<'_, Client>,
  url: String,
  opts: HttpRequestOptions
) -> Result<HttpResponse, String> {
  // Only the core API may be reached, whatever the webview asks for.
  let url = Url::parse(&url).map_err(|e| format!("invalid URL: {}", e))?;
  if !is_core_api_url(&url) {
    return Err("request denied: URL is not the Portmaster API".to_string());
  }

  // Build the request
  let mut req = client
    .request(Method::from_bytes(opts.method.as_bytes()).map_err(|e| e.to_string())?, url);

  // Apply headers
  for (k, v) in opts.headers {
    req = req.header(&k, &v);
  }

  // Attach body if present
  if let Some(body) = opts.body {
    req = req.body(body);
  }

  // Send and await the response
  let resp = req.send().await.map_err(|e| e.to_string())?;

  // Read status, headers, and body
  let status = resp.status().as_u16();
  let status_text = resp.status().canonical_reason().unwrap_or("").to_string();
  let headers = resp
    .headers()
    .iter()
    .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
    .collect();
  let body = resp.bytes().await.map_err(|e| e.to_string())?.to_vec();

  Ok(HttpResponse { status, status_text, headers, body })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed(url: &str) -> bool {
        is_core_api_url(&Url::parse(url).unwrap())
    }

    #[test]
    fn core_api_url_is_allowed() {
        assert!(allowed("http://127.0.0.1:817/api/v1/ping"));
        assert!(allowed("http://127.0.0.1:817"));
    }

    #[test]
    fn other_urls_are_denied() {
        assert!(!allowed("https://127.0.0.1:817/api/v1/ping"));
        assert!(!allowed("http://127.0.0.1:818/api/v1/ping"));
        assert!(!allowed("http://127.0.0.1/api/v1/ping"));
        assert!(!allowed("http://localhost:817/api/v1/ping"));
        assert!(!allowed("http://127.0.0.1.example.com:817/"));
        assert!(!allowed("http://example.com:817/?127.0.0.1"));
        assert!(!allowed("http://127.0.0.1:817@example.com/"));
        assert!(!allowed("http://user@127.0.0.1:817/"));
        assert!(!allowed("file:///etc/passwd"));
    }
}
