# AGENTS.md

## What this project is

taintguard is a hook for Claude Code and Codex. It blocks a shell or fetch command that uses a host the agent only saw in tool output, because text in a web page, file or command output may have planted it. It only looks at host names and IPv4 addresses in commands. It doesn't try to catch code that runs inside an install, or hosts that the agent rewrites or encodes.

## Commands

Every build, lint and test command lives in `scripts/harness-check.sh`. Don't copy the commands into CI or into other docs.

| Task | Command |
|---|---|
| Quick check (format, lint, tests) | `scripts/harness-check.sh quick` |
| Same as CI on Linux | `scripts/harness-check.sh ci-linux` |
| Same as CI on macOS | `scripts/harness-check.sh ci-macos` |
| Format | `cargo fmt` |

`.github/workflows/ci.yml` calls the script. If you add a check, add it to the script.

## Files

- `src/main.rs` reads one hook event, keeps the log for the session, and prints the block message.
- `src/hosts.rs` finds host names in text. Tool output and commands both go through it.
- `src/tlds.txt` is the official list of domain endings. To update it, download `https://data.iana.org/TLD/tlds-alpha-by-domain.txt` again.
- `tests/hook.rs` runs the real binary through a planted host, a block, an allowed host, and a user approval.

## What you need

- Rust with `rustfmt` and `clippy`.
- The `claude` and `codex` CLIs, if you want to test with a real agent.

## Problems you may run into

- Codex only loads hooks from a project's `.codex/` folder if you trust the project, and it skips any hook you haven't reviewed. For a one-off test, pass the hooks with `-c` and add `--dangerously-bypass-hook-trust`.
- `claude -p --allowedTools` takes more than one value, so it also swallows the prompt. Send the prompt on stdin instead.
- zsh reads `?` in a URL without quotes as a file pattern, so `curl https://example.com/?d=1` fails before the hook sees it. Put quotes around URLs in test files.
- `cargo fmt` rewraps the test tables. Run it before you edit those tables by exact text match.
- A new false block usually comes from code that ends like a real domain, e.g., `user.name`. Add that case to the test table in `src/hosts.rs` before you change the rules.
