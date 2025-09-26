// SPDX-License-Identifier: LGPL-3.0-or-later

use tiny_http::{Header, Response, StatusCode};

use std::io::Cursor;

/// Produces a 404 response that contains the endpoint in its json blob.
pub fn response_404(url: &str) -> Response<Cursor<Vec<u8>>> {
    json_response(&url, 404)
}

/// Produces a HTTP response with a json serialization of the given data
/// and the given status code.
///
/// The output json blob will be of the form `{ "data": [data], "status_code": [code] }`.
/// The status code will be embedded in the JSON as well as used as the HTTP status code.
///
/// # Panics
///
/// Panics if the provided object cannot be JSON-serialized.
pub fn json_response<S: serde::Serialize>(data: &S, status_code: u16) -> Response<Cursor<Vec<u8>>> {
    let hd_content_type = Header::from_bytes(
        b"Content-Type",
        b"application/json",
    ).unwrap();

    #[derive(serde::Serialize)]
    struct Resp<'s, S> {
        data: &'s S,
        status_code: u16,
    }

    let json = serde_json::to_vec(&Resp { data, status_code }).expect("cannot encode data as json");
    let json_len = json.len();
    
    Response::new(
        StatusCode::from(status_code),
        vec![hd_content_type],
        Cursor::new(json),
        Some(json_len),
        None,
    )
}
