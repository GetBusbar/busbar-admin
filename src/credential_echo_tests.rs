use super::*;
use std::io::{Read, Write};
use std::net::TcpListener;

const CANARY: &str = "bbk_CANARY_9f3c1e_do_not_print";

/// A one-shot HTTP/1.1 server answering every request with `200` and `body`.
fn serve_once(body: &'static str) -> String {
    serve_status("200 OK", body)
}

fn serve_status(status: &'static str, body: &'static str) -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = l.accept() {
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                match s.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            }
            let _ = write!(
                s,
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    format!("http://{addr}")
}

fn client(endpoint: &str) -> Client {
    Client::new(endpoint, "admin-token", Tls::default()).unwrap()
}

fn assert_no_canary(what: &str, e: &anyhow::Error) {
    for rendered in [format!("{e}"), format!("{e:#}"), format!("{e:?}")] {
        assert!(
            !rendered.contains(CANARY),
            "{what}: the minted credential reached the error text: {rendered}"
        );
    }
}

#[test]
fn a_mint_body_that_fails_to_decode_never_echoes_the_token() {
    // Version skew: the token decodes fine but a sibling field has the wrong type. The error
    // used to carry the WHOLE body, minted token included.
    let ep = serve_once(
        r#"{"id":"vk_1","name":"n","token":"bbk_CANARY_9f3c1e_do_not_print","expires_at":"soon"}"#,
    );
    let req = CreateKeyReq {
        name: "n".into(),
        allowed_pools: None,
        group: None,
        parent: None,
        expires_in: None,
        expires_at: None,
        labels: Default::default(),
        issue_aws_credential: false,
    };
    let e = client(&ep).create_key(&req).unwrap_err();
    assert_no_canary("create_key decode error", &e);
    assert!(format!("{e:#}").contains("decoding the gateway response"));
}

#[test]
fn a_decode_error_on_the_credential_itself_never_echoes_it() {
    // serde's own message quotes the offending value (`invalid type: string "…"`), so the
    // fix cannot simply drop the body and keep serde's Display.
    let ep = serve_once(
        r#"{"id":"vk_1","name":"n","token":"t","expires_at":"bbk_CANARY_9f3c1e_do_not_print"}"#,
    );
    let e = client(&ep).rotate_key("vk_1").unwrap_err();
    assert_no_canary("rotate_key decode error", &e);
}

#[test]
fn debug_of_a_minted_view_redacts_every_credential() {
    let c: CreatedKeyView = serde_json::from_str(
        r#"{"id":"vk_1","name":"n","token":"bbk_CANARY_9f3c1e_do_not_print",
            "aws_access_key_id":"AKIA1","aws_secret_access_key":"bbk_CANARY_9f3c1e_do_not_print"}"#,
    )
    .unwrap();
    let r: RotatedKeyView = serde_json::from_str(
        r#"{"id":"vk_1","name":"n","token":"bbk_CANARY_9f3c1e_do_not_print",
            "secret":"bbk_CANARY_9f3c1e_do_not_print"}"#,
    )
    .unwrap();
    for d in [
        format!("{c:?}"),
        format!("{c:#?}"),
        format!("{r:?}"),
        format!("{r:#?}"),
    ] {
        assert!(
            !d.contains(CANARY),
            "Debug printed a minted credential: {d}"
        );
    }
}

#[test]
fn json_output_still_carries_the_minted_credential_verbatim() {
    // `--json` is the documented way to capture the once-shown secret; redaction must be
    // confined to Debug and errors and leave the wire shape byte-identical.
    let raw = r#"{"id":"vk_1","name":"n","token":"bbk_CANARY_9f3c1e_do_not_print"}"#;
    let c: CreatedKeyView = serde_json::from_str(raw).unwrap();
    let v = serde_json::to_value(&c).unwrap();
    assert_eq!(v["token"], CANARY);
}

#[test]
fn error_responses_never_echo_credentials_or_terminal_controls() {
    for body in [
        CANARY,
        r#"{"error":{"code":"bbk_CANARY_9f3c1e_do_not_print","message":"bbk_CANARY_9f3c1e_do_not_print"}}"#,
    ] {
        let endpoint = serve_status("502 Bad Gateway", body);
        let error = client(&endpoint).info().unwrap_err();
        assert_no_canary("HTTP error", &error);
        assert!(error.to_string().contains("502"));
    }
}
