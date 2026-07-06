use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use ulid::Ulid;

pub fn generate_request_id() -> String {
    Ulid::new().to_string()
}

/// Middleware: injects a request ID header into the response.
pub async fn request_id_middleware(mut req: Request<axum::body::Body>, next: Next) -> Response {
    let request_id = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(generate_request_id);

    // Insert into request extensions for handlers to use
    req.extensions_mut().insert(request_id.clone());

    let mut response = next.run(req).await;
    response
        .headers_mut()
        .insert("x-request-id", request_id.parse().unwrap());
    response
}
