use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};

use assert_cmd::cargo::CommandCargoExt;
use assert_cmd::prelude::OutputAssertExt;
use ports::inspect::PortCollector;
use predicates::prelude::predicate;

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind test port");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

fn spawn_holder(port: u16) -> Child {
    Command::cargo_bin("ports")
        .expect("binary path")
        .arg("internal-hold-port")
        .arg(port.to_string())
        .spawn()
        .expect("spawn holder")
}

fn wait_for_port(port: u16) {
    let collector = PortCollector::new();
    let deadline = Instant::now() + Duration::from_secs(5);

    while Instant::now() < deadline {
        if collector
            .collect_port(port)
            .map(|details| !details.is_empty())
            .unwrap_or(false)
        {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }

    panic!("timed out waiting for port {port}");
}

#[test]
fn list_and_check_show_live_listener() {
    let port = free_port();
    let mut child = spawn_holder(port);
    wait_for_port(port);

    Command::cargo_bin("ports")
        .expect("binary path")
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains(port.to_string()));

    Command::cargo_bin("ports")
        .expect("binary path")
        .args(["check", &port.to_string()])
        .assert()
        .success()
        .stdout(predicate::str::contains(format!("Port {port}")));

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn list_and_check_support_json_output() {
    let port = free_port();
    let mut child = spawn_holder(port);
    wait_for_port(port);

    Command::cargo_bin("ports")
        .expect("binary path")
        .args(["--json", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"port\""));

    Command::cargo_bin("ports")
        .expect("binary path")
        .args(["--json", "check", &port.to_string()])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"is_free\": false"))
        .stdout(predicate::str::contains(format!("\"port\": {port}")));

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn kill_stops_live_listener() {
    let port = free_port();
    let mut child = spawn_holder(port);
    wait_for_port(port);

    Command::cargo_bin("ports")
        .expect("binary path")
        .args(["kill", &port.to_string()])
        .assert()
        .success()
        .stdout(predicate::str::contains(port.to_string()));

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if child.try_wait().expect("poll child").is_some() {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }

    let _ = child.kill();
    panic!("holder process was not terminated");
}
