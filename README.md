# pinentry-dispatch

A thin GnuPG **pinentry router** for macOS: Touch ID when you sit at the machine,
a terminal (curses) prompt when you reach it over SSH — so commit signing keeps
working, and still requires *you*, no matter where you are.

## The problem

`pinentry-mac` and `pinentry-touchid` are GUI programs. Over SSH there is no Aqua
session to draw them, so GnuPG signing fails with `Operation cancelled`.
`pinentry-touchid`'s only fallback is `pinentry-mac` — also GUI — so it cannot
recover in a remote session.

## How it works

`gpg-agent` is a launchd daemon, so a pinentry it spawns cannot see whether the
current operation originated from a local login or an SSH session. The reliable
place to know that is the **shell**, so detection lives there and rides the
standard `PINENTRY_USER_DATA` channel, which `gpg` forwards through `gpg-agent`
into the pinentry:

```
git commit → gpg → gpg-agent → pinentry-dispatch → exec the real pinentry
                                  ├─ PINENTRY_USER_DATA contains "curses" → pinentry-curses
                                  └─ otherwise                            → pinentry-touchid
```

Because the dispatcher `exec`s the chosen program (rather than proxying it), the
real pinentry talks Assuan to `gpg-agent` directly and receives `ttyname` and the
rest unchanged.

## Setup

1. Point `gpg-agent` at the dispatcher in `~/.gnupg/gpg-agent.conf`:

   ```
   pinentry-program /opt/homebrew/bin/pinentry-dispatch
   ```

2. Export the flag in interactive SSH shells (e.g. in `~/.zshrc`):

   ```sh
   [[ -n "$SSH_CONNECTION" ]] && export PINENTRY_USER_DATA=curses
   ```

3. Reload the agent: `gpgconf --kill gpg-agent`.

Local sessions leave `PINENTRY_USER_DATA` unset and keep using Touch ID.

## Build

```sh
cargo build --release
```

The two real pinentry paths are constants in `src/main.rs`; adjust them if your
Homebrew prefix differs.

## License

MIT
