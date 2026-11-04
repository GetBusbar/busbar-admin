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
