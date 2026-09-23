use proxmox_inventory_extract::cli::{Args, AuthMethod, resolve_credentials};
use clap::Parser;

#[test]
fn test_cli_defaults() {
    let args = Args::parse_from(["proxmox-inventory-extract", "-p", "secret"]);
    assert_eq!(args.host, "127.0.0.1:8006");
    assert_eq!(args.user, "root@pam");
    assert_eq!(args.password.as_deref(), Some("secret"));
    assert!(!args.verify_ssl);
    assert_eq!(args.timeout, 30);
    assert_eq!(args.workers, 8);
    assert!(!args.no_probe);
    assert_eq!(args.probe_timeout, 2.0);
    assert!(!args.quiet);
    assert!(args.output.is_none());
}

#[test]
fn test_resolve_credentials_precedence() {
    let args_token = Args::parse_from([
        "proxmox-inventory-extract",
        "-p", "mypass",
        "--api-token", "root@pam!token=uuid"
    ]);
    let auth = resolve_credentials(&args_token).unwrap();
    match auth {
        AuthMethod::ApiToken { token } => assert_eq!(token, "root@pam!token=uuid"),
        _ => panic!("Expected ApiToken"),
    }
}
