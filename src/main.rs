//! pinentry-dispatch — a self-contained GnuPG pinentry that picks how to ask.
//!
//! gpg-agent starts this as its `pinentry-program`. We speak Assuan ourselves,
//! decide which rung of the ladder to use, and for the terminal rungs hand the
//! conversation to a real pinentry — forwarding the options it needs, `ttyname`
//! above all, which is what pinentry-touchid gets wrong.
//!
//! Vocabulary (client, rung, ladder, delegate, route) is defined in CONTEXT.md.
//!
//! This stage has no Touch ID and no keychain: every conversation is delegated,
//! but only to a terminal the client actually sits on.

mod client;

use client::Client;
use std::env;
use std::ffi::OsString;
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;

/// gpg_err_make(GPG_ERR_SOURCE_PINENTRY, GPG_ERR_NO_PIN_ENTRY) — "no way to ask",
/// deliberately not GPG_ERR_CANCELED, which would claim the user refused.
const ERR_NO_PIN_ENTRY: u32 = (5 << 24) | 85;

const KNOWN_PREFIXES: [&str; 3] = ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"];

fn main() {
    let mut args = env::args().skip(1);
    if args.next().as_deref() == Some("--explain") {
        let pid = args.next().and_then(|a| a.parse().ok()).unwrap_or_else(|| {
            eprintln!("usage: pinentry-dispatch --explain <client-pid>");
            std::process::exit(2);
        });
        let client = Client::inspect(pid);
        println!("{}", client.describe());
        println!("local  = {}", client.is_local());
        println!("owns   = {} (against the tty gpg would report)", client.owns_tty(env::var("GPG_TTY").ok().as_deref()));
        return;
    }

    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let mut out = io::stdout();

    respond(&mut out, "OK Pleased to meet you");

    let mut pending: Vec<String> = Vec::new();
    let mut ttytype: Option<String> = None;
    let mut ttyname: Option<String> = None;
    let mut owner_pid: Option<u32> = None;

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => return,
            Ok(_) => {}
            Err(e) => {
                eprintln!("pinentry-dispatch: read failed: {e}");
                return;
            }
        }
        let line = line.trim_end_matches(['\r', '\n']).to_string();
        if line.is_empty() {
            continue;
        }
        let verb = line.split(' ').next().unwrap_or("").to_uppercase();

        match verb.as_str() {
            "BYE" => {
                respond(&mut out, "OK closing connection");
                return;
            }
            "NOP" => respond(&mut out, "OK"),
            "RESET" => {
                pending.clear();
                respond(&mut out, "OK");
            }
            "GETINFO" => {
                let answer = getinfo(line.split(' ').nth(1).unwrap_or(""));
                match answer {
                    Some(value) => {
                        respond(&mut out, &format!("D {value}"));
                        respond(&mut out, "OK");
                    }
                    None => respond(&mut out, "OK"),
                }
            }
            "GETPIN" | "CONFIRM" | "MESSAGE" => {
                delegate(
                    reader,
                    out,
                    &pending,
                    &line,
                    ttytype.as_deref(),
                    ttyname.as_deref(),
                    owner_pid,
                );
                return;
            }
            _ => {
                if let Some(value) = line.strip_prefix("OPTION ttytype=") {
                    ttytype = Some(value.to_string());
                }
                if let Some(value) = line.strip_prefix("OPTION ttyname=") {
                    ttyname = Some(value.to_string());
                }
                if let Some(value) = line.strip_prefix("OPTION owner=") {
                    owner_pid = parse_owner_pid(value);
                }
                pending.push(line);
                respond(&mut out, "OK");
            }
        }
    }
}

/// `OPTION owner=<pid>/<uid> <hostname>`; the hostname is gpg-agent's own machine,
/// so it tells us nothing about where the client is.
fn parse_owner_pid(value: &str) -> Option<u32> {
    value.split('/').next()?.trim().parse().ok()
}

fn respond(out: &mut io::Stdout, line: &str) {
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

/// The agent only logs these, so we answer for ourselves rather than for whichever
/// rung we have not picked yet. Claiming no features is deliberate: the agent then
/// strips the RS/US tab markers from SETDESC, which costs nothing and saves us
/// implementing tabbing.
fn getinfo(what: &str) -> Option<String> {
    match what {
        "version" => Some(env!("CARGO_PKG_VERSION").to_string()),
        "pid" => Some(std::process::id().to_string()),
        "flavor" => Some("dispatch".to_string()),
        "ttyinfo" => Some("- - - - -".to_string()),
        _ => None,
    }
}

/// A terminal that cannot address its cursor cannot draw the curses box, so the
/// plain line-based pinentry is the right one there — not a lesser one.
fn rung_order(ttytype: Option<&str>) -> [&'static str; 2] {
    if matches!(ttytype, None | Some("") | Some("dumb")) {
        ["pinentry-tty", "pinentry-curses"]
    } else {
        ["pinentry-curses", "pinentry-tty"]
    }
}

/// The second name is reached only when the first is not installed; a rung that
/// starts and then fails is not retried.
fn pick_terminal_rung(ttytype: Option<&str>) -> Option<PathBuf> {
    rung_order(ttytype).iter().find_map(|name| locate(name))
}

/// Never resolves the bare `pinentry` name: that is whatever the platform calls its
/// default, which on most Macs is the GUI one.
fn locate(name: &str) -> Option<PathBuf> {
    let from_path = env::var_os("PATH").unwrap_or_else(OsString::new);
    env::split_paths(&from_path)
        .chain(KNOWN_PREFIXES.iter().map(PathBuf::from))
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

fn delegate(
    reader: BufReader<io::StdinLock<'static>>,
    mut out: io::Stdout,
    pending: &[String],
    trigger: &str,
    ttytype: Option<&str>,
    ttyname: Option<&str>,
    owner_pid: Option<u32>,
) {
    let client = owner_pid.map(Client::inspect);
    match &client {
        Some(c) => eprintln!("pinentry-dispatch: client {}", c.describe()),
        None => eprintln!("pinentry-dispatch: no owner reported"),
    }
    if !client.as_ref().is_some_and(|c| c.owns_tty(ttyname)) {
        respond(
            &mut out,
            &format!("ERR {ERR_NO_PIN_ENTRY} no terminal the caller is sitting on; unlock the agent from a real terminal first"),
        );
        return;
    }

    let Some(binary) = pick_terminal_rung(ttytype) else {
        respond(
            &mut out,
            &format!("ERR {ERR_NO_PIN_ENTRY} no usable pinentry: not on this machine and no terminal to ask in"),
        );
        return;
    };

    let mut child = match Command::new(&binary)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            eprintln!("pinentry-dispatch: cannot start {}: {e}", binary.display());
            respond(
                &mut out,
                &format!("ERR {ERR_NO_PIN_ENTRY} cannot start {}", binary.display()),
            );
            return;
        }
    };

    eprintln!("pinentry-dispatch: route {}", binary.display());
    let mut to_child = child.stdin.take().expect("piped");
    let mut from_child = BufReader::new(child.stdout.take().expect("piped"));

    // The agent already has our OK for every one of these, so the replies belong to
    // us, not to it.
    let mut swallow = String::new();
    let _ = from_child.read_line(&mut swallow);
    for line in pending {
        if writeln!(to_child, "{line}").is_err() {
            break;
        }
        let _ = to_child.flush();
        swallow.clear();
        let _ = from_child.read_line(&mut swallow);
    }

    if writeln!(to_child, "{trigger}").is_err() {
        respond(&mut out, &format!("ERR {ERR_NO_PIN_ENTRY} delegate went away"));
        return;
    }
    let _ = to_child.flush();

    pump(reader, out, from_child, to_child, child);
}

/// Line by line rather than raw bytes: later stages watch this traffic for
/// CLEARPASSPHRASE and for the SETERROR that says the passphrase we supplied was wrong.
fn pump(
    mut reader: BufReader<io::StdinLock<'static>>,
    mut out: io::Stdout,
    mut from_child: BufReader<std::process::ChildStdout>,
    mut to_child: std::process::ChildStdin,
    mut child: Child,
) {
    let upstream = thread::spawn(move || loop {
        let mut line = String::new();
        match from_child.read_line(&mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        if write!(out, "{line}").is_err() || out.flush().is_err() {
            return;
        }
    });

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        if write!(to_child, "{line}").is_err() || to_child.flush().is_err() {
            break;
        }
        if line.trim_end().eq_ignore_ascii_case("BYE") {
            break;
        }
    }

    drop(to_child);
    let _ = upstream.join();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_terminals_get_the_line_based_rung_first() {
        for ttytype in [None, Some(""), Some("dumb")] {
            assert_eq!(rung_order(ttytype)[0], "pinentry-tty", "{ttytype:?}");
        }
    }

    #[test]
    fn capable_terminals_get_curses_first() {
        for ttytype in ["xterm-256color", "screen", "alacritty"] {
            assert_eq!(rung_order(Some(ttytype))[0], "pinentry-curses");
        }
    }

    #[test]
    fn the_two_rungs_are_the_same_pair_either_way() {
        let mut plain = rung_order(Some("dumb"));
        let mut capable = rung_order(Some("xterm-256color"));
        plain.sort_unstable();
        capable.sort_unstable();
        assert_eq!(plain, capable);
    }

    #[test]
    fn a_missing_binary_is_not_located() {
        assert!(locate("pinentry-does-not-exist-xyz").is_none());
    }

    #[test]
    fn owner_pid_is_the_part_before_the_slash() {
        assert_eq!(parse_owner_pid("28873/501 giggs-m1p"), Some(28873));
        assert_eq!(parse_owner_pid("nonsense"), None);
    }

    #[test]
    fn getinfo_never_claims_features() {
        assert_eq!(getinfo("flavor").as_deref(), Some("dispatch"));
        assert!(getinfo("unknown-query").is_none());
    }
}
