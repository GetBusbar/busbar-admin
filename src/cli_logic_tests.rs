use super::*;

#[test]
fn parse_labels_splits_on_first_equals_only() {
    // A value containing '=' (a URL query string, a base64 pad) must survive intact — the
    // split is on the FIRST '=', not all of them.
    let m = parse_labels(&["url=http://x?a=b".into(), "team=platform".into()]).unwrap();
    assert_eq!(m.get("url").map(String::as_str), Some("http://x?a=b"));
    assert_eq!(m.get("team").map(String::as_str), Some("platform"));
}

#[test]
fn parse_labels_rejects_a_pair_with_no_equals() {
    assert!(parse_labels(&["novalue".into()]).is_err());
}

#[test]
fn parse_labels_allows_empty_value() {
    let m = parse_labels(&["k=".into()]).unwrap();
    assert_eq!(m.get("k").map(String::as_str), Some(""));
}

// Calls the REAL `resolve_allowed_pools` that `cmd_keys_create` uses, never a copy of it: a
// test against a duplicated helper is tautological and stays green even when the shipped
// mapping regresses.
#[test]
fn allowed_pools_tristate_no_pools_is_empty_not_none() {
    assert_eq!(
        resolve_allowed_pools(true, &[]),
        Some(Vec::new()),
        "--no-pools => NO pools"
    );
    assert_eq!(
        resolve_allowed_pools(false, &[]),
        None,
        "omitted => ALL pools"
    );
    assert_eq!(
        resolve_allowed_pools(false, &["p1".into()]),
        Some(vec!["p1".into()]),
        "a list => exactly those pools"
    );
}

// ── credential output (CREDENTIAL-LOCKDOWN H11) ──────────────────────────────────────────

const CANARY: &str = "bbk_CANARY_9f3c1e_do_not_print";

fn created() -> CreatedKeyView {
    serde_json::from_str(
        r#"{"id":"vk_1","name":"svc","token":"bbk_CANARY_9f3c1e_do_not_print","expires_at":7,
            "aws_access_key_id":"AKIA1","aws_secret_access_key":"bbk_CANARY_9f3c1e_do_not_print"}"#,
    )
    .unwrap()
}

fn rotated() -> RotatedKeyView {
    serde_json::from_str(
        r#"{"id":"vk_1","name":"svc","token":"bbk_CANARY_9f3c1e_do_not_print","expires_at":7}"#,
    )
    .unwrap()
}

fn tmp(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("busbar-admin-test-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d.join(name)
}

#[test]
fn default_create_output_is_byte_identical() {
    let mut out = Vec::new();
    render_created(&created(), false, None, &mut out).unwrap();
    let want = [
        "created key vk_1 (svc)".to_string(),
        "  expires_at: 7 (unix seconds)".into(),
        String::new(),
        "  ┌─────────────────────────────────────────────────────────────┐".into(),
        "  │  TOKEN (shown once — store it now, it cannot be retrieved)  │".into(),
        "  └─────────────────────────────────────────────────────────────┘".into(),
        format!("  token: {CANARY}"),
        "  aws_access_key_id:     AKIA1".into(),
        format!("  aws_secret_access_key: {CANARY}  (shown once)"),
        String::new(),
    ]
    .join("\n");
    assert_eq!(String::from_utf8(out).unwrap(), want);

    let mut out = Vec::new();
    render_created(&created(), true, None, &mut out).unwrap();
    let want = format!("{}\n", serde_json::to_string_pretty(&created()).unwrap());
    assert_eq!(String::from_utf8(out).unwrap(), want);
}

#[test]
fn default_rotate_output_is_byte_identical() {
    let mut out = Vec::new();
    render_rotated(&rotated(), false, None, &mut out).unwrap();
    let want = [
        "rotated key vk_1 (svc)".to_string(),
        String::new(),
        "  ┌─────────────────────────────────────────────────────────────────┐".into(),
        "  │  NEW CREDENTIAL (shown once — the old one no longer resolves)  │".into(),
        "  └─────────────────────────────────────────────────────────────────┘".into(),
        format!("  token: {CANARY}"),
        "  expires_at: 7 (unix seconds)".into(),
        String::new(),
    ]
    .join("\n");
    assert_eq!(String::from_utf8(out).unwrap(), want);
}

#[test]
fn output_secret_to_keeps_every_credential_off_stdout() {
    for json in [false, true] {
        let sink = tmp(&format!("create-{json}.json"));
        let _ = std::fs::remove_file(&sink);
        let mut out = Vec::new();
        render_created(
            &created(),
            json,
            Some(&mut SecretSink::open(&sink).unwrap()),
            &mut out,
        )
        .unwrap();
        let shown = String::from_utf8(out).unwrap();
        assert!(
            !shown.contains(CANARY),
            "stdout carried the credential: {shown}"
        );
        let file = std::fs::read_to_string(&sink).unwrap();
        let v: serde_json::Value = serde_json::from_str(&file).unwrap();
        assert_eq!(v["token"], CANARY);
        assert_eq!(v["aws_secret_access_key"], CANARY);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&sink).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "the secret sink must be owner-only");
        }

        let sink = tmp(&format!("rotate-{json}.json"));
        let _ = std::fs::remove_file(&sink);
        let mut out = Vec::new();
        render_rotated(
            &rotated(),
            json,
            Some(&mut SecretSink::open(&sink).unwrap()),
            &mut out,
        )
        .unwrap();
        let shown = String::from_utf8(out).unwrap();
        assert!(
            !shown.contains(CANARY),
            "stdout carried the credential: {shown}"
        );
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&sink).unwrap()).unwrap();
        assert_eq!(v["token"], CANARY);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&sink).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn existing_permissive_secret_sinks_are_secured_for_both_renderers() {
    use std::os::unix::fs::PermissionsExt as _;

    for json in [false, true] {
        for rotate in [false, true] {
            let sink = tmp(&format!("existing-{rotate}-{json}.json"));
            std::fs::write(&sink, "old contents that must be replaced".repeat(100)).unwrap();
            std::fs::set_permissions(&sink, std::fs::Permissions::from_mode(0o644)).unwrap();
            let mut out = Vec::new();
            if rotate {
                render_rotated(
                    &rotated(),
                    json,
                    Some(&mut SecretSink::open(&sink).unwrap()),
                    &mut out,
                )
                .unwrap();
            } else {
                render_created(
                    &created(),
                    json,
                    Some(&mut SecretSink::open(&sink).unwrap()),
                    &mut out,
                )
                .unwrap();
            }
            assert_eq!(
                std::fs::metadata(&sink).unwrap().permissions().mode() & 0o777,
                0o600
            );
            let view: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&sink).unwrap()).unwrap();
            assert_eq!(view["token"], CANARY);
            assert!(!String::from_utf8(out).unwrap().contains(CANARY));
        }
    }
}

#[cfg(unix)]
#[test]
fn inherited_secret_descriptors_are_neither_chmodded_nor_truncated() {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::PermissionsExt as _;

    for rotate in [false, true] {
        let sink = tmp(&format!("inherited-{rotate}.json"));
        std::fs::write(&sink, "x".repeat(8192)).unwrap();
        std::fs::set_permissions(&sink, std::fs::Permissions::from_mode(0o640)).unwrap();
        let file = std::fs::OpenOptions::new().write(true).open(&sink).unwrap();
        let fd_path = std::path::PathBuf::from(format!("/dev/fd/{}", file.as_raw_fd()));
        let mut out = Vec::new();
        if rotate {
            render_rotated(
                &rotated(),
                true,
                Some(&mut SecretSink::open(&fd_path).unwrap()),
                &mut out,
            )
            .unwrap();
        } else {
            render_created(
                &created(),
                true,
                Some(&mut SecretSink::open(&fd_path).unwrap()),
                &mut out,
            )
            .unwrap();
        }
        let metadata = file.metadata().unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o640);
        assert_eq!(
            metadata.len(),
            8192,
            "an inherited sink must not be truncated"
        );
        assert!(std::fs::read_to_string(&sink).unwrap().contains(CANARY));
        assert!(!String::from_utf8(out).unwrap().contains(CANARY));
    }
}

#[test]
fn token_file_is_read_and_its_contents_never_reach_an_error() {
    let f = tmp("token");
    std::fs::write(&f, format!("{CANARY}\n")).unwrap();
    let (t, argv) = resolve_token(None, None, Some(&f)).unwrap();
    assert_eq!(t.as_str(), CANARY);
    assert!(!argv);

    let e = resolve_token(Some("x"), Some(ValueSource::CommandLine), Some(&f)).unwrap_err();
    assert!(!format!("{e:#}").contains(CANARY));

    let missing = tmp("absent-token");
    let e = resolve_token(None, None, Some(&missing)).unwrap_err();
    assert!(format!("{e:#}").contains("--token-file"));
}

#[test]
fn token_file_wins_over_the_env_token() {
    let f = tmp("token-env");
    std::fs::write(&f, "from-file\r\n").unwrap();
    let (t, _) = resolve_token(Some("from-env"), Some(ValueSource::EnvVariable), Some(&f)).unwrap();
    assert_eq!(t.as_str(), "from-file");
}

#[test]
fn only_an_argv_token_is_flagged_for_the_warning() {
    let m = Cli::command()
        .try_get_matches_from(["busbar-admin", "--token", "t", "info"])
        .unwrap();
    let (_, argv) = resolve_token(Some("t"), m.value_source("token"), None).unwrap();
    assert!(argv, "--token on argv must warn");

    let m = Cli::command()
        .try_get_matches_from(["busbar-admin", "info", "--token", "t"])
        .unwrap();
    assert_eq!(m.value_source("token"), Some(ValueSource::CommandLine));

    let (_, argv) = resolve_token(Some("t"), Some(ValueSource::EnvVariable), None).unwrap();
    assert!(!argv, "the env token must not warn");
}

#[cfg(unix)]
#[test]
fn replacing_a_secret_sink_does_not_disclose_to_existing_readers() {
    use std::io::Read as _;
    let path = tmp("old-reader.json");
    std::fs::write(&path, "old-public-content").unwrap();
    let mut old_reader = std::fs::File::open(&path).unwrap();
    let mut sink = SecretSink::open(&path).unwrap();
    sink.write(&created()).unwrap();
    let mut old = String::new();
    old_reader.read_to_string(&mut old).unwrap();
    assert_eq!(old, "old-public-content");
    assert!(std::fs::read_to_string(&path).unwrap().contains(CANARY));
}

#[test]
fn invalid_secret_destination_prevents_rotation_request() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let client = Client::new(
        &format!("http://{}", listener.local_addr().unwrap()),
        "token",
        Tls::default(),
    )
    .unwrap();
    let missing = tmp("missing-parent").join("secret.json");
    assert!(cmd_keys_rotate(&client, "vk_1", true, Some(&missing)).is_err());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn unused_secret_sink_preserves_previous_contents() {
    let path = tmp("untouched-secret.json");
    std::fs::write(&path, "old").unwrap();
    let sink = SecretSink::open(&path).unwrap();
    let temporary = sink.temporary.clone().unwrap();
    drop(sink);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "old");
    assert!(!temporary.exists());
}

#[test]
fn competing_secret_writers_fail_before_minting() {
    let path = tmp("competing-secret.json");
    let first = SecretSink::open(&path).unwrap();
    assert!(SecretSink::open(&path).is_err());
    drop(first);
    assert!(SecretSink::open(&path).is_ok());
}

#[test]
fn human_output_escapes_terminal_controls_and_preserves_valid_text() {
    assert_eq!(terminal_text("normal café"), "normal café");
    assert_eq!(terminal_text("name\n\u{1b}[2J\r"), "name\\n\\u{1b}[2J\\r");
    let mut value = created();
    value.name = "\u{1b}]52;clipboard\u{7}".into();
    let mut output = Vec::new();
    render_created(&value, false, None, &mut output).unwrap();
    assert!(!output.contains(&0x1b));
    assert!(!output.contains(&7));
}

#[test]
fn json_output_propagates_broken_pipe_without_panicking() {
    struct Closed;
    impl Write for Closed {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let error = write_json(&serde_json::json!({"a":1}), &mut Closed).unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::BrokenPipe
    );
}

#[test]
fn failed_credential_write_retains_private_recovery_file() {
    let path = tmp("failed-write.json");
    let mut sink = SecretSink::open(&path).unwrap();
    let temporary = sink.temporary.clone().unwrap();
    std::fs::write(&temporary, "partial credential bytes").unwrap();
    sink.file = std::fs::File::open(&temporary).unwrap();
    let error = sink.write(&created()).unwrap_err();
    assert!(format!("{error:#}").contains("may be incomplete"));
    drop(sink);
    assert_eq!(
        std::fs::read_to_string(&temporary).unwrap(),
        "partial credential bytes"
    );
    std::fs::remove_file(temporary).unwrap();
}
