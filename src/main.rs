//! pinentry-dispatch — a thin GnuPG pinentry router.
//!
//! gpg-agent spawns this as its `pinentry-program`. We do nothing but pick the
//! real pinentry and `exec` into it, so the chosen program talks Assuan to
//! gpg-agent directly (inheriting stdio and receiving `ttyname` etc. unchanged).
//!
//! The decision rides on `PINENTRY_USER_DATA`, which gpg forwards from the
//! calling shell's environment through gpg-agent into the pinentry. An
//! interactive SSH shell exports `PINENTRY_USER_DATA=curses`; a local session
//! leaves it unset. So:
//!
//!   * contains "curses"  -> pinentry-curses   (terminal TUI, works over SSH)
//!   * otherwise          -> pinentry-touchid  (Touch ID on the local machine)
//!
//! Detection lives in the shell on purpose: gpg-agent is a launchd daemon, so a
//! pinentry it spawns cannot itself tell whether the operation came from SSH.

use std::env;
use std::os::unix::process::CommandExt;
use std::process::Command;

const TOUCHID: &str = "/opt/homebrew/opt/pinentry-touchid/bin/pinentry-touchid";
const CURSES: &str = "/opt/homebrew/bin/pinentry-curses";

fn main() {
    let want_curses = env::var("PINENTRY_USER_DATA")
        .map(|v| v.contains("curses"))
        .unwrap_or(false);

    let target = if want_curses { CURSES } else { TOUCHID };

    // exec replaces this process; it only returns if the exec itself fails.
    let err = Command::new(target).args(env::args_os().skip(1)).exec();

    eprintln!("pinentry-dispatch: failed to exec {target}: {err}");
    std::process::exit(127);
}
