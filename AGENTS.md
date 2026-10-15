# AGENTS.md

## Objective and scope

taintguard is a hook for Claude Code and Codex. It denies a shell or fetch call when the call uses a host that the agent saw only in tool output, because injected text in a web page, file or command output may have put that host there. The scope is hostnames and IPv4 addresses in tool calls. Code that runs inside a package install, paraphrased hosts and encoded hosts are out of scope.

## Commands

All build, lint and test commands live in `scripts/harness-check.sh`. Do not copy them into CI or into other docs.

| Task | Command |
|---|---|
| Fast local check (fmt, clippy, tests) | `scripts/harness-check.sh quick` |
| CI parity on Linux | `scripts/harness-check.sh ci-linux` |
| CI parity on macOS | `scripts/harness-check.sh ci-macos` |
| Format | `cargo fmt` |

CI calls `scripts/harness-check.sh ci-linux` and `scripts/harness-check.sh ci-macos` from `.github/workflows/ci.yml`. If you add a check, add it to the script.

## Layout

- `src/main.rs` reads one hook event, keeps the per-session log, and writes the deny decision.
- `src/hosts.rs` finds hostnames in text. Both the output side and the call side use it.
- `src/tlds.txt` is the IANA TLD list. To refresh it, download `https://data.iana.org/TLD/tlds-alpha-by-domain.txt` again.
- `tests/hook.rs` runs the binary through an injection, a deny, an allow-list pass and a user approval.

## Prerequisites

- A stable Rust toolchain with `rustfmt` and `clippy`.
- For live tests, the `claude` and `codex` CLIs.

## Known failure patterns

- Codex loads project hooks only when the project `.codex/` layer is trusted, and it skips any hook whose hash you have not reviewed. For a one-off test, pass the hooks with `-c` and add `--dangerously-bypass-hook-trust`.
- `claude -p --allowedTools` takes several values, so it also takes the prompt as a value. Pass the prompt on stdin.
- zsh treats `?` in an unquoted URL as a glob, so a test command like `curl https://example.com/?d=1` fails before the hook sees it. Quote URLs in test fixtures.
- `cargo fmt` reflows the test tables. Run it before you edit the tables with exact string matches.
- A new false deny usually comes from a code token that ends in a real TLD. Add a case to the table in `src/hosts.rs` before you change the rules.
