//! pinentry-dispatch — a self-contained GnuPG pinentry that picks how to ask.
//!
//! gpg-agent starts this as its `pinentry-program`. We speak Assuan ourselves, work
//! out who is asking and from where, and either answer with Touch ID or hand the
//! conversation to a real terminal pinentry — forwarding the options it needs,
//! `ttyname` above all, which is what pinentry-touchid fails to do.
//!
//! Vocabulary (client, rung, ladder, delegate, route) is defined in CONTEXT.md.

mod client;
mod keychain;
mod touchid;

use client::Client;
use keychain::Store;
use std::env;
use std::ffi::OsString;
use std::io::{self, BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

/// gpg_err_make(GPG_ERR_SOURCE_PINENTRY, GPG_ERR_NO_PIN_ENTRY) — "no way to ask",
/// deliberately not CANCELED, which would claim the person refused.
const ERR_NO_PIN_ENTRY: u32 = (5 << 24) | 85;
const ERR_CANCELED: u32 = (5 << 24) | 99;

const KNOWN_PREFIXES: [&str; 3] = ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"];

#[derive(Default)]
struct Conversation {
    pending: Vec<String>,
    ttytype: Option<String>,
    ttyname: Option<String>,
    owner_pid: Option<u32>,
    keygrip: Option<String>,
    external_cache_allowed: bool,
    asking_for_a_new_passphrase: bool,
    override_rung: Option<String>,
    already_answered_from_store: bool,
}

impl Conversation {
    fn note(&mut self, line: &str) {
        if let Some(v) = line.strip_prefix("OPTION ttytype=") {
            self.ttytype = Some(v.to_string());
        } else if let Some(v) = line.strip_prefix("OPTION ttyname=") {
            self.ttyname = Some(v.to_string());
        } else if let Some(v) = line.strip_prefix("OPTION owner=") {
            self.owner_pid = parse_owner_pid(v);
        } else if let Some(v) = line.strip_prefix("OPTION pinentry-user-data=") {
            self.override_rung = Some(v.to_lowercase());
        } else if line.starts_with("OPTION allow-external-password-cache") {
            self.external_cache_allowed = true;
        } else if let Some(v) = line.strip_prefix("SETKEYINFO ") {
            self.keygrip = normal_mode_keygrip(v);
        } else if line.starts_with("SETREPEAT") {
            self.asking_for_a_new_passphrase = true;
        }
    }

    /// Writes one line to the caller's own terminal. Same rule as delegating: only
    /// when the caller really is sitting on the terminal it reported, never on a tty
    /// some stale environment variable happens to name.
    fn tell_caller(&self, message: &str) {
        let Some(ttyname) = self.ttyname.as_deref() else {
            return;
        };
        if !self.owner_pid.map(Client::inspect).is_some_and(|c| c.owns_tty(Some(ttyname))) {
            return;
        }
        if let Ok(mut tty) = std::fs::OpenOptions::new().write(true).open(ttyname) {
            let _ = writeln!(tty, "\r\n{message}");
        }
    }

    /// Touch ID needs every one of these. A missing stored passphrase is one of them,
    /// so the first signing after installation goes to the terminal and the answer it
    /// collects becomes the stored one — no separate setup step.
    ///
    /// Returns the first condition that failed, so a signing that quietly went to the
    /// terminal can say which one it was.
    fn touch_id_blocker(&self, store: &Option<Store>) -> Option<&'static str> {
        if self.already_answered_from_store {
            return Some("the stored passphrase was already offered and refused");
        }
        if self.asking_for_a_new_passphrase {
            return Some("this is a new passphrase (SETREPEAT)");
        }
        if !self.external_cache_allowed {
            return Some("agent did not allow an external cache");
        }
        let Some(keygrip) = &self.keygrip else {
            return Some("no keygrip (not SETKEYINFO n/...)");
        };
        let Some(store) = store else {
            return Some("no keychain");
        };
        if !(store.has(keygrip) || store.has_legacy(keygrip)) {
            return Some("nothing stored for this key");
        }
        if !self.owner_pid.map(Client::inspect).is_some_and(|c| c.is_local()) {
            return Some("caller is not local");
        }
        if !touchid::available() {
            return Some("biometrics unavailable in this process");
        }
        None
    }
}

fn main() {
    let mut args = env::args().skip(1);
    if args.next().as_deref() == Some("doctor") {
        return doctor(args.collect());
    }

    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin.lock());
    let mut out = io::stdout();
    let store = Store::open();
    let mut talk = Conversation::default();

    respond(&mut out, "OK Pleased to meet you");

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        let line = line.trim_end_matches(['\r', '\n']).to_string();
        if line.is_empty() {
            continue;
        }

        match line.split(' ').next().unwrap_or("").to_uppercase().as_str() {
            "BYE" => {
                respond(&mut out, "OK closing connection");
                return;
            }
            "NOP" => respond(&mut out, "OK"),
            "RESET" => {
                talk = Conversation::default();
                respond(&mut out, "OK");
            }
            "GETINFO" => match getinfo(line.split(' ').nth(1).unwrap_or("")) {
                Some(value) => {
                    respond(&mut out, &format!("D {value}"));
                    respond(&mut out, "OK");
                }
                None => respond(&mut out, "OK"),
            },
            // The agent sends this when a passphrase we supplied turned out to be wrong.
            // The agent sends this when a passphrase we supplied was rejected. It then
            // gives up on the whole signing, and what the person sees is gpg's terse
            // "Bad passphrase" for something they never typed — so say what happened,
            // on their own terminal, before that is all they have to go on.
            "CLEARPASSPHRASE" => {
                let grip = clearpassphrase_keygrip(&line).or_else(|| talk.keygrip.clone());
                if let (Some(store), Some(grip)) = (&store, grip) {
                    if store.forget(&grip) {
                        note(&format!("forgot stored passphrase for {grip}"));
                        talk.tell_caller(
                            "pinentry-dispatch: the stored passphrase was rejected and has been \
                             removed from the keychain. Signing will ask for it again, and the \
                             answer you give will be stored in its place.",
                        );
                    }
                }
                respond(&mut out, "OK");
            }
            "GETPIN" => {
                if let Some(answer) = try_touch_id(&talk, &store) {
                    match answer {
                        Answer::Passphrase(secret) => {
                            note("route touch-id (answered from store)");
                            talk.already_answered_from_store = true;
                            respond(&mut out, "S PASSWORD_FROM_CACHE");
                            respond(&mut out, &format!("D {}", escape(&secret)));
                            respond(&mut out, "OK");
                        }
                        Answer::Refused => {
                            note("route touch-id (refused by user)");
                            respond(&mut out, &format!("ERR {ERR_CANCELED} Operation cancelled"));
                        }
                    }
                    continue;
                }
                delegate(reader, out, &talk, &line, store);
                return;
            }
            "CONFIRM" | "MESSAGE" => {
                delegate(reader, out, &talk, &line, store);
                return;
            }
            _ => {
                talk.note(&line);
                talk.pending.push(line);
                respond(&mut out, "OK");
            }
        }
    }
}

enum Answer {
    Passphrase(String),
    Refused,
}

fn try_touch_id(talk: &Conversation, store: &Option<Store>) -> Option<Answer> {
    if let Some(blocker) = talk.touch_id_blocker(store) {
        note(&format!("touch-id skipped: {blocker}"));
        return None;
    }
    let keygrip = talk.keygrip.as_ref()?;
    let store = store.as_ref()?;
    let secret = store.get(keygrip).or_else(|| store.adopt_legacy(keygrip))?;

    match touchid::authenticate("unlock your GPG key") {
        touchid::Outcome::Approved => Some(Answer::Passphrase(secret)),
        touchid::Outcome::Refused => Some(Answer::Refused),
        touchid::Outcome::TryAnotherRung => None,
    }
}

/// Says which rung this situation would reach and what each condition contributed.
/// Run it from the terminal you are asking about: without `--client` it inspects
/// itself, which stands in for the gpg that would be asking from the same place.
fn doctor(args: Vec<String>) {
    let pid = flag(&args, "--client")
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(std::process::id);
    let keygrip = flag(&args, "--keygrip").or_else(default_signing_keygrip);
    let ttyname = env::var("GPG_TTY").ok();

    let client = Client::inspect(pid);
    let store = Store::open();

    println!("client    {}", client.describe());
    println!("GPG_TTY   {}", ttyname.as_deref().unwrap_or("(unset)"));
    println!();

    let local = client.is_local();
    let owns = client.owns_tty(ttyname.as_deref());
    let biometrics = touchid::available();
    let stored = keygrip.as_ref().zip(store.as_ref()).map(|(grip, store)| {
        (store.has(grip), store.has_legacy(grip))
    });

    println!("local           {local}");
    println!("biometrics      {biometrics}");
    println!("owns terminal   {owns}");
    match (&keygrip, stored) {
        (Some(grip), Some((ours, legacy))) => {
            println!("keygrip         {grip}");
            println!("stored          ours={ours} legacy={legacy}");
        }
        (Some(grip), None) => println!("keygrip         {grip} (no keychain)"),
        (None, _) => println!("keygrip         unknown — pass --keygrip to check storage"),
    }
    println!();

    let has_item = stored.is_some_and(|(ours, legacy)| ours || legacy);
    let route = if local && biometrics && has_item {
        "Touch ID".to_string()
    } else if owns {
        match pick_terminal_rung(env::var("TERM").ok().as_deref()) {
            Some(path) => path.display().to_string(),
            None => "nothing — no terminal pinentry installed".to_string(),
        }
    } else {
        "nothing — would refuse with No pinentry".to_string()
    };
    println!("route           {route}");
    if !local {
        println!("  note: not local, so Touch ID is out even if biometrics work here");
    }
    if local && biometrics && !has_item && owns {
        println!("  note: nothing stored yet — the first signing goes to the terminal and stores its answer");
    }
    if !owns && !(local && biometrics && has_item) {
        println!("  note: GPG_TTY does not name this process's controlling terminal");
    }
}

fn flag(args: &[String], name: &str) -> Option<String> {
    let at = args.iter().position(|a| a == name)?;
    args.get(at + 1).cloned()
}

fn default_signing_keygrip() -> Option<String> {
    let key = Command::new("git")
        .args(["config", "--get", "user.signingkey"])
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    let key = String::from_utf8_lossy(&key.stdout).trim().to_string();
    let listing = Command::new("gpg")
        .args(["--list-secret-keys", "--with-keygrip", "--keyid-format", "LONG", &key])
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    String::from_utf8_lossy(&listing.stdout)
        .lines()
        .find_map(|line| line.trim().strip_prefix("Keygrip = "))
        .map(str::to_string)
}

/// `SETKEYINFO n/<keygrip>` is an ordinary key. `u/` carries a cache id the calling
/// program chose for itself, so answering those from the store would let any local
/// program name a string and be handed the secret behind one fingerprint.
fn normal_mode_keygrip(value: &str) -> Option<String> {
    value.strip_prefix("n/").map(|grip| grip.trim().to_string())
}

/// The agent sends this in a conversation of its own, with no SETKEYINFO before it,
/// so the key has to be read out of the command itself.
fn clearpassphrase_keygrip(line: &str) -> Option<String> {
    normal_mode_keygrip(line.split_once(' ')?.1.trim())
}

/// `OPTION owner=<pid>/<uid> <hostname>`; the hostname is gpg-agent's own machine,
/// so it says nothing about where the client is.
fn parse_owner_pid(value: &str) -> Option<u32> {
    value.split('/').next()?.trim().parse().ok()
}

fn escape(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '%' => "%25".to_string(),
            '\r' => "%0D".to_string(),
            '\n' => "%0A".to_string(),
            other => other.to_string(),
        })
        .collect()
}

fn unescape(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&text[i + 1..i + 3], 16) {
                out.push(byte as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Our stderr lands in gpg-agent's log, which is not where anyone looks. With
/// `PINENTRY_DISPATCH_LOG` set in the environment the agent was started from, the
/// route taken is written somewhere a person can read.
fn note(message: &str) {
    eprintln!("pinentry-dispatch: {message}");
    if let Ok(path) = env::var("PINENTRY_DISPATCH_LOG") {
        if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "{message}");
        }
    }
}

fn respond(out: &mut io::Stdout, line: &str) {
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

/// The agent only logs these, so we answer for ourselves rather than for a rung we
/// have not picked yet. Claiming no features is deliberate: the agent then strips the
/// tab markers from SETDESC, which costs nothing and saves implementing tabbing.
fn getinfo(what: &str) -> Option<String> {
    match what {
        "version" => Some(env!("CARGO_PKG_VERSION").to_string()),
        "pid" => Some(std::process::id().to_string()),
        "flavor" => Some("dispatch".to_string()),
        "ttyinfo" => Some("- - - - -".to_string()),
        _ => None,
    }
}

/// A terminal that cannot address its cursor cannot draw the curses box, so the plain
/// line-based pinentry is the right one there — not a lesser one.
fn rung_order(ttytype: Option<&str>) -> [&'static str; 2] {
    if matches!(ttytype, None | Some("") | Some("dumb")) {
        ["pinentry-tty", "pinentry-curses"]
    } else {
        ["pinentry-curses", "pinentry-tty"]
    }
}

/// The second name is reached only when the first is not installed; a rung that starts
/// and then fails is not retried.
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

#[derive(Default)]
struct Delegated {
    supplied: Option<String>,
    rejected: bool,
}

fn delegate(
    reader: BufReader<io::StdinLock<'static>>,
    mut out: io::Stdout,
    talk: &Conversation,
    trigger: &str,
    store: Option<Store>,
) {
    let client = talk.owner_pid.map(Client::inspect);
    match &client {
        Some(c) => note(&format!("client {}", c.describe())),
        None => note("no owner reported"),
    }
    if !client.as_ref().is_some_and(|c| c.owns_tty(talk.ttyname.as_deref())) {
        respond(
            &mut out,
            &format!("ERR {ERR_NO_PIN_ENTRY} no terminal the caller is sitting on"),
        );
        note("route none (caller does not own the reported terminal)");
        return;
    }

    let Some(binary) = pick_terminal_rung(talk.ttytype.as_deref()) else {
        respond(&mut out, &format!("ERR {ERR_NO_PIN_ENTRY} no terminal pinentry installed"));
        return;
    };

    let mut child = match Command::new(&binary)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            note(&format!("cannot start {}: {e}", binary.display()));
            respond(&mut out, &format!("ERR {ERR_NO_PIN_ENTRY} cannot start {}", binary.display()));
            return;
        }
    };
    note(&format!("route delegate {}", binary.display()));

    let mut to_child = child.stdin.take().expect("piped");
    let mut from_child = BufReader::new(child.stdout.take().expect("piped"));

    // The agent already has our OK for every one of these, so the replies are ours.
    let mut swallow = String::new();
    let _ = from_child.read_line(&mut swallow);
    for line in &talk.pending {
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

    let seen = pump(reader, out, from_child, to_child, child);

    // "The agent never complained" is the only evidence available that the passphrase
    // was right, and it is available here: a wrong one comes back as SETERROR before
    // the next GETPIN, in this same conversation.
    if let (Some(store), Some(keygrip), Some(secret)) = (&store, &talk.keygrip, &seen.supplied) {
        if !seen.rejected && talk.external_cache_allowed && !talk.asking_for_a_new_passphrase {
            if store.put(keygrip, secret) {
                note(&format!("stored passphrase for {keygrip}"));
            }
        }
    }
}

/// Line by line rather than raw bytes, so the passphrase the delegate collected and
/// the agent's verdict on it are both visible here.
fn pump(
    mut reader: BufReader<io::StdinLock<'static>>,
    mut out: io::Stdout,
    mut from_child: BufReader<std::process::ChildStdout>,
    mut to_child: std::process::ChildStdin,
    mut child: Child,
) -> Delegated {
    let seen = Arc::new(Mutex::new(Delegated::default()));

    let upstream = {
        let seen = Arc::clone(&seen);
        thread::spawn(move || loop {
            let mut line = String::new();
            match from_child.read_line(&mut line) {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
            if let Some(data) = line.trim_end().strip_prefix("D ") {
                seen.lock().unwrap().supplied = Some(unescape(data));
            }
            if write!(out, "{line}").is_err() || out.flush().is_err() {
                return;
            }
        })
    };

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let verb = line.split(' ').next().unwrap_or("").trim_end().to_uppercase();
        if verb == "SETERROR" {
            let mut seen = seen.lock().unwrap();
            seen.rejected = true;
            seen.supplied = None;
        }
        if write!(to_child, "{line}").is_err() || to_child.flush().is_err() {
            break;
        }
        if verb == "BYE" {
            break;
        }
    }

    drop(to_child);
    let _ = upstream.join();
    let _ = child.wait();
    Arc::try_unwrap(seen).map(|m| m.into_inner().unwrap()).unwrap_or_default()
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
    fn only_normal_mode_yields_a_keygrip() {
        assert_eq!(normal_mode_keygrip("n/ABC123").as_deref(), Some("ABC123"));
        assert_eq!(normal_mode_keygrip("u/whatever-i-chose"), None);
        assert_eq!(normal_mode_keygrip("s/ABC123"), None);
        assert_eq!(normal_mode_keygrip("--clear"), None);
    }

    #[test]
    fn escaping_round_trips_the_characters_assuan_reserves() {
        for secret in ["plain", "100%", "with\nnewline", "carriage\rreturn", "%25 already"] {
            assert_eq!(unescape(&escape(secret)), secret, "{secret:?}");
        }
    }

    #[test]
    fn touch_id_needs_every_precondition() {
        let mut talk = Conversation {
            external_cache_allowed: true,
            keygrip: Some("ABC".into()),
            ..Default::default()
        };
        assert_eq!(talk.touch_id_blocker(&None), Some("no keychain"));
        talk.external_cache_allowed = false;
        assert_eq!(talk.touch_id_blocker(&None), Some("agent did not allow an external cache"));
        talk.external_cache_allowed = true;
        talk.asking_for_a_new_passphrase = true;
        assert_eq!(
            talk.touch_id_blocker(&None),
            Some("this is a new passphrase (SETREPEAT)")
        );
    }

    #[test]
    fn the_key_to_forget_comes_from_the_command_not_from_earlier_state() {
        assert_eq!(clearpassphrase_keygrip("CLEARPASSPHRASE n/ABC123").as_deref(), Some("ABC123"));
        assert_eq!(clearpassphrase_keygrip("CLEARPASSPHRASE u/mine"), None);
        assert_eq!(clearpassphrase_keygrip("CLEARPASSPHRASE"), None);
    }

    #[test]
    fn getinfo_never_claims_features() {
        assert_eq!(getinfo("flavor").as_deref(), Some("dispatch"));
        assert!(getinfo("unknown-query").is_none());
    }
}
