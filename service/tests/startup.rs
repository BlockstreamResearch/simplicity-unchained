use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use simplicity_unchained_core::utils::generate_keypair;
use tempfile::{NamedTempFile, TempDir};

struct ServiceProcess(Child);

impl ServiceProcess {
    fn spawn(directory: &Path, config: Option<&Path>) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_service"));
        command.arg("start").current_dir(directory);
        if let Some(config) = config {
            command.arg("--config").arg(config);
        }
        Self(
            command
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        )
    }

    fn assert_failure(&mut self, expected: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                assert!(
                    !status.success(),
                    "startup unexpectedly exited successfully"
                );
                let mut logs = String::new();
                self.0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut logs)
                    .unwrap();
                self.0
                    .stderr
                    .take()
                    .unwrap()
                    .read_to_string(&mut logs)
                    .unwrap();
                assert!(logs.contains(expected), "missing startup error: {expected}");
                return logs;
            }
            assert!(Instant::now() < deadline, "startup did not fail promptly");
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for ServiceProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn configuration(key: &str, port: u16) -> String {
    format!(
        "[service]\nport = {port}\nprivate_key = \"{key}\"\n\
         elements_network = \"liquidtestnet\"\nbitcoin_network = \"testnet4\"\n"
    )
}

fn write_configuration(directory: &Path, contents: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new_in(directory).unwrap();
    file.write_all(contents.as_bytes()).unwrap();
    file
}

#[test]
fn missing_configuration_exits_unsuccessfully() {
    let directory = TempDir::new().unwrap();
    ServiceProcess::spawn(directory.path(), None).assert_failure("Failed to load config");
    ServiceProcess::spawn(
        directory.path(),
        Some(&directory.path().join("missing.toml")),
    )
    .assert_failure("Failed to load config");
    ServiceProcess::spawn(directory.path(), Some(directory.path()))
        .assert_failure("Failed to load config");
}

#[test]
fn missing_empty_and_invalid_keys_fail_closed() {
    let directory = TempDir::new().unwrap();
    for (key, error) in [
        ("".to_string(), "Invalid private key"),
        ("not-hex".to_string(), "Invalid private key hex"),
        (hex::encode([0; 32]), "Invalid private key"),
        (hex::encode([1; 31]), "Invalid private key"),
    ] {
        let file = write_configuration(directory.path(), &configuration(&key, 0));
        ServiceProcess::spawn(directory.path(), Some(file.path())).assert_failure(error);
    }
    let file = write_configuration(
        directory.path(),
        "[service]\nport = 0\nelements_network = \"liquidtestnet\"\nbitcoin_network = \"testnet4\"\n",
    );
    ServiceProcess::spawn(directory.path(), Some(file.path()))
        .assert_failure("failed to parse config");
}

#[test]
fn malformed_configuration_does_not_log_private_key_contents() {
    let directory = TempDir::new().unwrap();
    let marker = "must-not-appear-in-logs";
    let file = write_configuration(
        directory.path(),
        &configuration(marker, 0).replace(
            &format!("private_key = \"{marker}\""),
            &format!("private_key = \"{marker}\" invalid"),
        ),
    );
    let logs = ServiceProcess::spawn(directory.path(), Some(file.path()))
        .assert_failure("failed to parse config");
    assert!(!logs.contains(marker));
}

#[test]
fn invalid_networks_exit_unsuccessfully() {
    let directory = TempDir::new().unwrap();
    let (secret_key, _) = generate_keypair();
    let config = configuration(&hex::encode(secret_key.secret_bytes()), 0);
    for (network, error) in [
        ("liquidtestnet", "Failed to parse Elements network"),
        ("testnet4", "Failed to parse Bitcoin network"),
    ] {
        let file = write_configuration(
            directory.path(),
            &config.replace(network, "invalid-network"),
        );
        ServiceProcess::spawn(directory.path(), Some(file.path())).assert_failure(error);
    }
}

#[test]
fn occupied_port_exits_unsuccessfully() {
    let directory = TempDir::new().unwrap();
    let listener = TcpListener::bind("0.0.0.0:0").unwrap();
    let (secret_key, _) = generate_keypair();
    let file = write_configuration(
        directory.path(),
        &configuration(
            &hex::encode(secret_key.secret_bytes()),
            listener.local_addr().unwrap().port(),
        ),
    );
    ServiceProcess::spawn(directory.path(), Some(file.path())).assert_failure("Failed to bind");
}

#[test]
fn explicit_read_only_configuration_starts_and_serves_requests() {
    let directory = TempDir::new().unwrap();
    let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    let (secret_key, _) = generate_keypair();
    let file = write_configuration(
        directory.path(),
        &configuration(&hex::encode(secret_key.secret_bytes()), address.port()),
    );
    let mut permissions = fs::metadata(file.path()).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(file.path(), permissions).unwrap();
    drop(reservation);
    let mut process = ServiceProcess::spawn(directory.path(), Some(file.path()));
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut connection = loop {
        assert!(
            process.0.try_wait().unwrap().is_none(),
            "service exited during startup"
        );
        if let Ok(connection) = TcpStream::connect_timeout(&address, Duration::from_millis(100)) {
            break connection;
        }
        assert!(Instant::now() < deadline, "service did not become ready");
        thread::sleep(Duration::from_millis(10));
    };
    connection
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    connection.write_all(
        b"GET /simplicity-unchained/version HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    ).unwrap();
    let mut response = String::new();
    connection.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.contains("\"version\":"));
}

#[test]
fn shipped_example_has_no_usable_key() {
    let example: toml::Value = toml::from_str(include_str!("../config.example.toml")).unwrap();
    assert_eq!(example["service"]["private_key"].as_str(), Some(""));
    let directory = TempDir::new().unwrap();
    let file = write_configuration(directory.path(), include_str!("../config.example.toml"));
    ServiceProcess::spawn(directory.path(), Some(file.path()))
        .assert_failure("Invalid private key");
}
