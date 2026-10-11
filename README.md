# pinentry-dispatch

A GnuPG pinentry for macOS that works out **how to ask you** for the passphrase:
Touch ID when you are at the machine, a terminal prompt when you are not — so
signing keeps working over SSH, inside tmux or herdr, and from tools that have no
terminal at all, and still requires *you* either way.

## The problem

`pinentry-mac` and `pinentry-touchid` draw in the window server, so over SSH there
is nothing to draw on and signing fails. `pinentry-touchid` nominally falls back to
another pinentry, but it hands the conversation over without forwarding the terminal
the caller is attached to, so the terminal pinentry it starts has nowhere to draw
either — which makes the fallback useless in exactly the case it exists for.

The usual workaround is to tell the pinentry which way to ask by exporting
`PINENTRY_USER_DATA` from your shell. That is decided when the shell starts, and a
tmux or herdr pane keeps its birth environment for as long as it lives: a pane born
over SSH will still say "SSH" when you are sitting in front of the machine, and the
reverse. `GPG_TTY` has the same problem and is worse — plenty of shells never set it,
and when it is set it can name a terminal that has belonged to someone else for days.

## How it works

`gpg-agent` is long-lived, so a pinentry it starts inherits an environment that says
nothing about the present. But the agent does tell the pinentry the **process id of
the client that asked** (`OPTION owner`), and that process is the present. From it
we read the environment that matters, walk its ancestry, and — most importantly —
ask the kernel which terminal it is actually attached to, rather than believing a
variable about it.

The rungs are tried in order, and the first one whose conditions hold is used for the
whole conversation:

| Rung | Used when |
|---|---|
| Touch ID | the caller is on this machine, biometrics are available, and a passphrase for this key is already stored |
| `pinentry-curses` | the caller has a terminal that can address its cursor |
| `pinentry-tty` | the caller has a terminal that cannot (`TERM` is `dumb` or unset) |
| — | none of the above: signing fails with `No pinentry` rather than drawing somewhere nobody is looking |

There is no falling back after a rung has started. Choosing happens before the
conversation is handed over, which is the same shape upstream's own pinentries use
when they pick between a GUI and curses.

Refusing at the Touch ID prompt ends the signing; pressing its **Use passphrase**
button moves to the terminal instead. A refusal is not turned into another question.

## Install

```sh
brew install giggs-lynx/tap/pinentry-dispatch
```

Then point `gpg-agent` at it, in `~/.gnupg/gpg-agent.conf`:

```
pinentry-program /opt/homebrew/bin/pinentry-dispatch
```

and reload: `gpgconf --reload gpg-agent`.

Nothing else. No shell configuration, no `PINENTRY_USER_DATA`, no change to git's
`gpg.program`. If `PINENTRY_USER_DATA` is set anyway it is honoured as an explicit
override, which is useful when you disagree with the decision.

## The stored passphrase

The first signing for a key goes to the terminal, and the answer it collects is kept
in your login keychain under the service `pinentry-dispatch`, keyed by the key's
keygrip. From then on Touch ID answers for it. There is no setup step; the first
prompt is the setup.

An existing `pinentry-touchid` entry is adopted on first use, so you keep your
passphrase. The old entry is not deleted.

If the stored passphrase stops being right — because you changed it — the agent
rejects it and tells us to forget it. That signing fails once, with GnuPG's terse
`Bad passphrase` for something you never typed, so a line explaining what happened is
written to your own terminal. The next signing asks you and stores the new answer.

The keychain binds access to the program's code signature, so the first use after an
upgrade asks you to authorise it once.

## Diagnosing

```sh
pinentry-dispatch doctor
```

says which rung the current situation would reach and what each condition
contributed. Run it from the terminal you are asking about. `pinentry-dispatch --version`
prints the installed version.

Set `PINENTRY_DISPATCH_LOG` in the environment `gpg-agent` is started from to record
the route of every signing to that file — useful when a prompt appears somewhere you
did not expect, or does not appear at all.

## Build

```sh
cargo build --release
```

## License

MIT
