use super::*;

#[test]
fn key_ids_cannot_change_the_operation_path() {
    assert_eq!(
        Client::key_path("vk_target/revoke#", "/rotate").unwrap(),
        "/keys/vk_target%2Frevoke%23/rotate"
    );
    assert_eq!(
        Client::key_path("vk_target?x=y", "").unwrap(),
        "/keys/vk_target%3Fx=y"
    );
    assert_eq!(
        Client::key_path("vk_1", "/rotate").unwrap(),
        "/keys/vk_1/rotate"
    );
    for id in ["", ".", ".."] {
        assert!(Client::key_path(id, "").is_err());
    }
}

#[test]
fn endpoint_and_token_validation_never_echo_secrets() {
    for endpoint in [
        "https://user:secret@localhost",
        "https://localhost?token=secret",
        "https://localhost#secret",
        "file:///secret",
    ] {
        let error = Client::new(endpoint, "token", Tls::default())
            .err()
            .unwrap();
        assert!(!format!("{error:#}").contains("secret"));
    }
    for token in ["", "a\tb", "a\nb", "a\u{7f}b"] {
        assert!(Client::new("http://localhost", token, Tls::default()).is_err());
    }
}

#[test]
fn local_reads_enforce_the_limit_before_accumulating_the_whole_file() {
    let path = std::env::temp_dir().join(format!("busbar-read-limit-{}", std::process::id()));
    std::fs::write(&path, b"123456789").unwrap();
    assert!(read_local(&path, 8, "test input").is_err());
    assert_eq!(
        read_local(&path, 9, "test input").unwrap().as_slice(),
        b"123456789"
    );
    std::fs::remove_file(path).unwrap();
}

#[test]
fn oversized_response_is_refused_from_headers_without_reading_body() {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let worker = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = [0; 4096];
        let _ = stream.read(&mut request).unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 33554433\r\nConnection: close\r\n\r\n")
            .unwrap();
    });
    let client = Client::new(&format!("http://{address}"), "token", Tls::default()).unwrap();
    assert!(client.info().unwrap_err().to_string().contains("32 MiB"));
    worker.join().unwrap();
}

#[test]
fn config_apply_preserves_the_restart_required_planes() {
    let view: ConfigApplyView =
        serde_json::from_str(r#"{"applied":true,"config_version":7,"reload_to_apply":["admin"]}"#)
            .unwrap();
    assert_eq!(view.reload_to_apply, vec!["admin"]);
    assert_eq!(
        serde_json::to_value(view).unwrap()["reload_to_apply"],
        serde_json::json!(["admin"])
    );
}

#[test]
fn streaming_responses_without_length_are_bounded() {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let worker = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = [0; 4096];
        let _ = stream.read(&mut request).unwrap();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
            .unwrap();
        for _ in 0..513 {
            if stream.write_all(&[b' '; 64 * 1024]).is_err() {
                break;
            }
        }
    });
    let client = Client::new(&format!("http://{address}"), "token", Tls::default()).unwrap();
    assert!(client.info().unwrap_err().to_string().contains("32 MiB"));
    worker.join().unwrap();
}

#[test]
fn old_config_apply_responses_do_not_gain_an_empty_restart_field() {
    let view: ConfigApplyView =
        serde_json::from_str(r#"{"applied":true,"config_version":1,"note":"ok"}"#).unwrap();
    assert!(serde_json::to_value(view)
        .unwrap()
        .get("reload_to_apply")
        .is_none());
}

/// The streamed plugin upload body must be the exact bytes the serde route produced
/// (`serde_json::to_vec` of the request struct over a whole-tarball base64 string), across chunk
/// boundaries, padding remainders and names that need JSON escapes.
#[test]
fn streamed_plugin_body_is_byte_identical_to_the_serde_request() {
    use base64::Engine as _;
    let dir = std::env::temp_dir().join(format!("busbar-upload-body-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("plugin.tar.gz");
    let sizes = [
        0,
        1,
        2,
        3,
        4,
        UPLOAD_CHUNK - 1,
        UPLOAD_CHUNK,
        UPLOAD_CHUNK + 1,
        2 * UPLOAD_CHUNK + 2,
    ];
    for size in sizes {
        let bytes: Vec<u8> = (0..size).map(|i| (i * 31 + 7) as u8).collect();
        std::fs::write(&path, &bytes).unwrap();
        for name in ["plugin.tar.gz", "q\"uo\\te\u{1}\u{7f}é.tar.gz", ""] {
            let expected = serde_json::to_vec(&InstallPluginReq {
                file: name.to_owned(),
                tarball_b64: base64::engine::general_purpose::STANDARD.encode(&bytes),
            })
            .unwrap();
            let inspect = serde_json::to_vec(&InspectPluginReq {
                file: name.to_owned(),
                tarball_b64: base64::engine::general_purpose::STANDARD.encode(&bytes),
            })
            .unwrap();
            assert_eq!(
                expected, inspect,
                "install and inspect share one wire shape"
            );
            let streamed =
                plugin_upload_body(&path, Some(name), 1 << 20, "plugin tarball").unwrap();
            assert_eq!(streamed, expected, "size {size}, name {name:?}");
        }
    }
    std::fs::remove_dir_all(dir).unwrap();
}

/// Same refusals, same wording and the same precedence as the whole-file read it replaced: open,
/// then the size limit, and only then the missing file name.
#[test]
fn streamed_plugin_body_keeps_the_read_local_refusals() {
    let dir = std::env::temp_dir().join(format!("busbar-upload-refuse-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let missing = dir.join("absent.tar.gz");
    let error = plugin_upload_body(&missing, None, 8, "plugin tarball").unwrap_err();
    assert!(format!("{error:#}").starts_with("opening plugin tarball "));

    let path = dir.join("big.tar.gz");
    std::fs::write(&path, vec![7u8; UPLOAD_CHUNK + 9]).unwrap();
    for limit in [8, UPLOAD_CHUNK as u64 + 8] {
        let error = plugin_upload_body(&path, None, limit, "plugin tarball").unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("plugin tarball exceeds its {limit}-byte limit")
        );
    }
    assert!(
        plugin_upload_body(&path, Some("x"), UPLOAD_CHUNK as u64 + 9, "plugin tarball").is_ok()
    );
    let error =
        plugin_upload_body(&path, None, UPLOAD_CHUNK as u64 + 9, "plugin tarball").unwrap_err();
    assert_eq!(
        error.to_string(),
        "tarball path has no usable filename; pass --file"
    );
    std::fs::remove_dir_all(dir).unwrap();
}

/// A plain-`http` endpoint skips the root store only; `https` always loads it.
#[test]
fn only_plain_http_can_skip_the_root_store() {
    assert!(!skip_built_in_roots("https"));
    let proxied = PROXY_ENV.iter().any(|v| std::env::var_os(v).is_some());
    assert_eq!(skip_built_in_roots("http"), !proxied);
}

/// A pre-encoded body goes out with the same `Content-Type` and bytes `RequestBuilder::json`
/// sends, and the response still decodes.
#[test]
fn pre_encoded_json_body_matches_the_json_builder_request() {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let worker = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        let mut chunk = [0; 4096];
        while !request.ends_with(b"{\"a\":[1,2.50]}") {
            let n = stream.read(&mut chunk).unwrap();
            assert!(n > 0, "request ended early");
            request.extend_from_slice(&chunk[..n]);
        }
        let body = br#"{"applied":true,"config_version":3}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .unwrap();
        stream.write_all(body).unwrap();
        String::from_utf8(request).unwrap().to_ascii_lowercase()
    });
    let client = Client::new(&format!("http://{address}"), "token", Tls::default()).unwrap();
    let value: serde_json::Value = serde_json::from_str(r#"{ "a" : [1, 2.50] }"#).unwrap();
    let view = client
        .config_apply(serde_json::to_vec(&value).unwrap())
        .unwrap();
    assert!(view.applied);
    assert_eq!(view.config_version, 3);
    let request = worker.join().unwrap();
    assert!(request.starts_with("post /api/v1/admin/config/apply "));
    assert!(request.contains("\r\ncontent-type: application/json\r\n"));
    assert!(request.contains("\r\ncontent-length: 14\r\n"));
}
