//! What we can learn about the process that asked for the passphrase.
//!
//! Our own environment is useless here: gpg-agent is long-lived and its children
//! inherit whatever it was started with, which on a multiplexed machine is some
//! pane's environment frozen days ago. gpg-agent hands us the client's pid in
//! `OPTION owner`, so we ask about that process instead.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

pub struct Client {
    pub pid: u32,
    env: HashMap<String, String>,
    controlling_tty: Option<String>,
}

impl Client {
    pub fn inspect(pid: u32) -> Self {
        Self {
            pid,
            env: read_env(pid),
            controlling_tty: read_controlling_tty(pid),
        }
    }

    /// An empty map means the read failed, not that the process has no variables —
    /// SIP hides the environment of Apple's own binaries. Unknown counts as remote:
    /// asking in a terminal costs a typed passphrase, whereas guessing "local" pops
    /// Touch ID for a caller we could not identify.
    pub fn env_readable(&self) -> bool {
        !self.env.is_empty()
    }

    /// Local means the same person is at this machine's screen — not merely that the
    /// process runs here, which is also true of everything reached over SSH.
    pub fn is_local(&self) -> bool {
        if !self.env_readable() {
            return false;
        }
        if self.env.get("HERDR_ENV").is_some_and(|v| v == "1") {
            return !any_herdr_client_over_ssh();
        }
        if let Some(socket) = self.env.get("TMUX") {
            return !tmux_session_is_over_ssh(socket);
        }
        !(self.env.contains_key("SSH_CONNECTION") || self.env.contains_key("SSH_TTY"))
    }

    /// `ttyname` is whatever the client's GPG_TTY said, which survives in a pane's
    /// environment long after that terminal belonged to someone else. Drawing on it
    /// would put a dialog on an unrelated pane — under tmux control mode that tears
    /// the pane apart — so it counts only when the client really is sitting on it.
    pub fn owns_tty(&self, ttyname: Option<&str>) -> bool {
        let Some(ttyname) = ttyname.filter(|name| !name.is_empty()) else {
            return false;
        };
        let Some(actual) = self.controlling_tty.as_deref() else {
            return false;
        };
        let claimed = Path::new(ttyname).file_name().and_then(|n| n.to_str());
        claimed == Some(actual) && Path::new(ttyname).exists()
    }

    pub fn describe(&self) -> String {
        let mux = if self.env.contains_key("HERDR_ENV") {
            "herdr"
        } else if self.env.contains_key("TMUX") {
            "tmux"
        } else {
            "none"
        };
        format!(
            "pid={} env={} mux={} tty={} ssh_connection={}",
            self.pid,
            if self.env_readable() { "readable" } else { "UNREADABLE" },
            mux,
            self.controlling_tty.as_deref().unwrap_or("-"),
            if self.env.contains_key("SSH_CONNECTION") { "set" } else { "unset" },
        )
    }
}

/// `ps -E` prints the argument vector and the environment run together with nothing
/// between them, so picking out `KEY=VALUE` tokens by shape also picks up arguments
/// that happen to look like assignments. Asking twice and subtracting the arguments
/// leaves exactly the environment.
///
/// `-ww` matters: without it the output stops at 80 columns and every lookup silently
/// misses. An empty result means Apple's binaries hide their environment under SIP
/// (/bin/zsh does); the client we care about is gpg, which does not.
fn read_env(pid: u32) -> HashMap<String, String> {
    let pid = pid.to_string();
    let Some(with_env) = run(&["ps", "-wwE", "-p", &pid, "-o", "args="]) else {
        return HashMap::new();
    };
    let Some(argv) = run(&["ps", "-ww", "-p", &pid, "-o", "args="]) else {
        return HashMap::new();
    };
    let environ = with_env
        .trim_end()
        .strip_prefix(argv.trim_end())
        .unwrap_or("");
    environ
        .split_whitespace()
        .filter_map(|token| token.split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

fn read_controlling_tty(pid: u32) -> Option<String> {
    let text = run(&["ps", "-o", "tty=", "-p", &pid.to_string()])?;
    let tty = text.trim();
    (!tty.is_empty() && tty != "??").then(|| tty.to_string())
}

/// A herdr pane's ancestry leads to the shared server, which only says how the server
/// was started — not who is attached now. The attached clients are separate processes,
/// so we look at those instead.
fn any_herdr_client_over_ssh() -> bool {
    let Some(pids) = run(&["pgrep", "-x", "herdr"]) else {
        return false;
    };
    pids.split_whitespace()
        .filter_map(|pid| pid.parse::<u32>().ok())
        .filter(|pid| !run(&["ps", "-o", "command=", "-p", &pid.to_string()])
            .is_some_and(|cmd| cmd.contains(" server")))
        .any(has_sshd_ancestor)
}

fn has_sshd_ancestor(pid: u32) -> bool {
    let mut current = pid;
    for _ in 0..32 {
        let Some(parent) = run(&["ps", "-o", "ppid=", "-p", &current.to_string()])
            .and_then(|text| text.trim().parse::<u32>().ok())
        else {
            return false;
        };
        if parent <= 1 {
            return false;
        }
        if run(&["ps", "-o", "comm=", "-p", &parent.to_string()])
            .is_some_and(|comm| comm.contains("sshd"))
        {
            return true;
        }
        current = parent;
    }
    false
}

/// tmux refreshes the session environment on every attach, so this answers "who is
/// looking now", unlike the variables frozen into the pane at birth.
fn tmux_session_is_over_ssh(socket: &str) -> bool {
    Command::new("tmux")
        .args(["show-environment", "SSH_CONNECTION"])
        .env("TMUX", socket)
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).starts_with("SSH_CONNECTION="))
        .unwrap_or(false)
}

fn run(argv: &[&str]) -> Option<String> {
    let out = Command::new(argv[0]).args(&argv[1..]).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}
