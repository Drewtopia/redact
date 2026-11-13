//! Finding the parts of a text to hide, and swapping them for placeholders.

use crate::pack::{Loaded, Remember};
use aho_corasick::AhoCorasick;
use hmac::{Hmac, KeyInit, Mac};
use regex::Regex;
use serde::Serialize;
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

/// One part of the text to hide, as byte offsets. It never carries the value
/// itself, so `--json` output is safe to log.
#[derive(Serialize, Debug, Clone)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub label: String,
    pub pack: String,
    pub rule: String,
}

/// A value found by a rule, to hide everywhere else it appears too.
struct Word {
    text: String,
    label: String,
    pack: String,
    rule: String,
}

fn distinctive(v: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\S\s+\S|[-_.0-9]|[a-z][A-Z]").unwrap())
        .is_match(v)
}

fn chosen_name(v: &str) -> bool {
    v.chars().any(|c| c.is_uppercase()) || v.chars().count() >= 5
}

/// One JSON object's own fields: the pieces of it outside any nested object, as
/// (offset, text), plus those pieces joined, for the `within` test.
struct Record<'a> {
    pieces: Vec<(usize, &'a str)>,
    joined: String,
}

/// Every object in the text, each with only its own fields, so a nested object
/// (`"user": {…}`) between two fields does not split them apart and field order
/// does not matter. Braces inside JSON strings are not structure. Text outside
/// every object counts as one more record; an unclosed object runs to the end.
fn records(text: &str) -> Vec<Record<'_>> {
    let b = text.as_bytes();
    // Each open object: its finished pieces, and where its current piece began.
    let mut stack: Vec<(Vec<(usize, usize)>, usize)> = vec![(Vec::new(), 0)];
    let mut done: Vec<Vec<(usize, usize)>> = Vec::new();
    let (mut in_string, mut escaped) = (false, false);
    for (i, &c) in b.iter().enumerate() {
        if in_string {
            match c {
                _ if escaped => escaped = false,
                b'\\' => escaped = true,
                b'"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match c {
            b'"' => in_string = true,
            b'{' => {
                let top = stack
                    .last_mut()
                    .expect("the outermost record is never popped here");
                if i > top.1 {
                    top.0.push((top.1, i));
                }
                stack.push((Vec::new(), i + 1));
            }
            b'}' if stack.len() > 1 => {
                let (mut pieces, start) = stack.pop().expect("checked above");
                if i > start {
                    pieces.push((start, i));
                }
                done.push(pieces);
                stack.last_mut().expect("the outermost record remains").1 = i + 1;
            }
            _ => {}
        }
    }
    while let Some((mut pieces, start)) = stack.pop() {
        if b.len() > start {
            pieces.push((start, b.len()));
        }
        done.push(pieces);
    }
    // Braces and quotes are ASCII, so every cut is on a character boundary.
    done.into_iter()
        .filter(|p| !p.is_empty())
        .map(|p| {
            let pieces: Vec<(usize, &str)> = p.into_iter().map(|(s, e)| (s, &text[s..e])).collect();
            let joined = pieces
                .iter()
                .map(|(_, t)| *t)
                .collect::<Vec<_>>()
                .join("\n");
            Record { pieces, joined }
        })
        .collect()
}

pub fn scan(text: &str, loaded: &Loaded) -> Result<Vec<Span>, String> {
    // Keywords are a cheap test that a pack or rule could match at all.
    let low = text.to_lowercase();
    let has = |keys: &[String]| keys.is_empty() || keys.iter().any(|k| low.contains(k.as_str()));
    // Built on first use, and only if a `within` rule runs.
    let recs: OnceLock<Vec<Record>> = OnceLock::new();

    let mut spans = Vec::new();
    let mut words: Vec<Word> = Vec::new();
    let mut remembered: HashSet<String> = HashSet::new();

    for pack in &loaded.packs {
        if !has(&pack.keywords) {
            continue;
        }
        for rule in &pack.rules {
            if !has(&rule.keywords) {
                continue;
            }
            let segments: Vec<(usize, &str)> = match &rule.within {
                None => vec![(0, text)],
                Some(w) => recs
                    .get_or_init(|| records(text))
                    .iter()
                    .filter(|r| w.is_match(&r.joined))
                    .flat_map(|r| r.pieces.iter().copied())
                    .collect(),
            };
            for (offset, seg) in segments {
                for caps in rule.re.captures_iter(seg) {
                    let Some(m) = caps.get(rule.group) else {
                        continue;
                    };
                    // Trailing whitespace is not part of a value: on a CRLF line
                    // the `\r` would otherwise stick to a remembered name.
                    let value = m.as_str().trim_end();
                    if value.is_empty() || pack.allow.contains(&value.to_lowercase()) {
                        continue;
                    }
                    spans.push(Span {
                        start: offset + m.start(),
                        end: offset + m.start() + value.len(),
                        label: rule.label.clone(),
                        pack: pack.id.clone(),
                        rule: rule.id.clone(),
                    });
                    let keep = match rule.remember {
                        Remember::No => false,
                        Remember::Distinctive => distinctive(value),
                        Remember::Any => chosen_name(value),
                    };
                    // Stored once, not once per match: email-dense input made
                    // one copy per address.
                    if keep && remembered.insert(value.to_string()) {
                        words.push(Word {
                            text: value.to_string(),
                            label: rule.label.clone(),
                            pack: pack.id.clone(),
                            rule: rule.id.clone(),
                        });
                    }
                }
            }
        }
    }

    for list in &loaded.words {
        for w in &list.words {
            words.push(Word {
                text: w.clone(),
                label: list.label.clone(),
                pack: "words".into(),
                rule: list.label.clone(),
            });
        }
    }
    // A label is a key or file name (`CONTOSO_TOKEN`, `contoso.txt`), so it can
    // hold a word being hidden. Such a label becomes a plain VALUE.
    let hidden: Vec<String> = words
        .iter()
        .map(|w| label_key(&w.text))
        .filter(|w| w.chars().count() >= 3)
        .collect();
    spans.extend(find_words(text, words)?);
    let mut safe: HashMap<String, String> = HashMap::new();
    for s in &mut spans {
        let label = safe
            .entry(s.label.clone())
            .or_insert_with(|| {
                let key = label_key(&s.label);
                if hidden.iter().any(|w| key.contains(w.as_str())) {
                    "VALUE".to_string()
                } else {
                    s.label.clone()
                }
            })
            .clone();
        s.label = label;
    }
    Ok(merge(spans))
}

/// Lower case with `-`, `_` and spaces folded together, to compare labels and words.
fn label_key(s: &str) -> String {
    s.to_lowercase().replace(['_', ' '], "-")
}

/// Every remembered value and listed word, as a whole word, in any case.
///
/// One Aho-Corasick pass finds every word at once, however many there are (a
/// regex of thousands of alternatives grew past its size limit and took 25 s on
/// 1 MB). Overlapping matches are all kept; `merge` then keeps the earliest and
/// longest, so `Fabrikam Holdings` wins over `Fabrikam`. Case is ignored for
/// ASCII letters only: `ÄBC` does not match `äbc`.
fn find_words(text: &str, words: Vec<Word>) -> Result<Vec<Span>, String> {
    if words.is_empty() {
        return Ok(Vec::new());
    }
    let mut seen = HashSet::new();
    let words: Vec<Word> = words
        .into_iter()
        .filter(|w| seen.insert(w.text.to_ascii_lowercase()))
        .collect();
    let ac = AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(words.iter().map(|w| &w.text))
        .map_err(|e| format!("cannot build the word matcher: {e}"))?;
    // A word edge that is a letter or digit must not touch another letter or
    // digit, so `Contoso` is not found inside `Contosoville`. Anything else is an
    // edge: punctuation of any script (`Contoso’s`, `«Contoso»`) and `_`, so a
    // name inside `rg_contoso_prod` or `CONTOSO_API_KEY` is still found. Matches
    // are whole UTF-8 sequences, so slicing at them is on character boundaries.
    let mut out = Vec::new();
    for m in ac.find_overlapping_iter(text) {
        let w = &words[m.pattern().as_usize()];
        let (start, end) = (m.start(), m.end());
        let alnum = |c: Option<char>| c.is_some_and(char::is_alphanumeric);
        let (first, last) = (w.text.chars().next(), w.text.chars().next_back());
        if (alnum(first) && alnum(text[..start].chars().next_back()))
            || (alnum(last) && alnum(text[end..].chars().next()))
        {
            continue;
        }
        out.push(Span {
            start,
            end,
            label: w.label.clone(),
            pack: w.pack.clone(),
            rule: w.rule.clone(),
        });
    }
    Ok(out)
}

/// Sorted, and overlapping finds joined into one span covering every byte any
/// of them found: a later find that runs past an earlier one must not leave its
/// tail showing. The earliest (then longest) find gives the joined span its label.
fn merge(mut spans: Vec<Span>) -> Vec<Span> {
    spans.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    let mut out: Vec<Span> = Vec::new();
    for s in spans {
        match out.last_mut() {
            Some(l) if s.start < l.end => l.end = l.end.max(s.end),
            _ => out.push(s),
        }
    }
    out
}

/// Makes placeholder tags: `[LABEL-` + the first 8 hex characters of
/// HMAC-SHA256(key, value) + `]`.
///
/// - With `REDACT_KEY` set, the same value gets the same tag in every run that
///   uses that key, so several `redact` calls in one session agree.
/// - Without it, the key is 32 random bytes made fresh for each run.
///
/// Either way a tag cannot be worked back to its value without the key: a plain
/// `sha256("Fabrikam")` could be, by hashing guesses. Two values that would share a tag
/// are told apart: the second is re-hashed with a counter until its tag is free.
pub struct Tagger {
    key: Vec<u8>,
    by_value: HashMap<String, String>,
    used: HashSet<String>,
}

impl Tagger {
    /// The shortest `REDACT_KEY` accepted: a short key can be guessed, and with it every tag.
    pub const MIN_KEY_LEN: usize = 16;

    pub fn new(key: Option<&str>) -> Result<Self, String> {
        let key = match key.filter(|k| !k.is_empty()) {
            Some(k) if k.len() < Self::MIN_KEY_LEN => {
                return Err(format!(
                    "REDACT_KEY is {} characters; use at least {} (e.g. export REDACT_KEY=$(openssl rand -hex 32))",
                    k.len(),
                    Self::MIN_KEY_LEN
                ));
            }
            Some(k) => k.as_bytes().to_vec(),
            None => {
                let mut k = vec![0u8; 32];
                getrandom::fill(&mut k)
                    .map_err(|e| format!("no secure random source for the tag key: {e}"))?;
                k
            }
        };
        Ok(Self {
            key,
            by_value: HashMap::new(),
            used: HashSet::new(),
        })
    }

    pub fn tag(&mut self, label: &str, value: &str) -> String {
        if let Some(t) = self.by_value.get(value) {
            return t.clone();
        }
        let mut n: u32 = 0;
        let tag = loop {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC takes any key length");
            mac.update(value.as_bytes());
            if n > 0 {
                mac.update(&[0]);
                mac.update(&n.to_be_bytes());
            }
            let digest = mac.finalize().into_bytes();
            let hex: String = digest[..4].iter().map(|b| format!("{b:02x}")).collect();
            if self.used.insert(hex.clone()) {
                break format!("[{label}-{hex}]");
            }
            n += 1;
        };
        self.by_value.insert(value.to_string(), tag.clone());
        tag
    }
}

/// The text with each span swapped for its tag.
pub fn mask(text: &str, spans: &[Span], tagger: &mut Tagger) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for s in spans {
        out.push_str(&text[last..s.start]);
        out.push_str(&tagger.tag(&s.label, &text[s.start..s.end]));
        last = s.end;
    }
    out.push_str(&text[last..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack;

    #[test]
    fn a_key_gives_the_same_tag_every_run_and_no_key_does_not_link_runs() {
        let key = Some("0123456789abcdef0123");
        assert_eq!(
            Tagger::new(key).unwrap().tag("ORG", "fabrikam"),
            Tagger::new(key).unwrap().tag("ORG", "fabrikam")
        );
        assert_ne!(
            Tagger::new(key).unwrap().tag("ORG", "fabrikam"),
            Tagger::new(Some("another-key-0123456"))
                .unwrap()
                .tag("ORG", "fabrikam")
        );
        assert_ne!(
            Tagger::new(None).unwrap().tag("ORG", "fabrikam"),
            Tagger::new(None).unwrap().tag("ORG", "fabrikam")
        );
    }

    #[test]
    fn a_short_key_is_refused() {
        assert!(
            Tagger::new(Some("short"))
                .err()
                .unwrap()
                .contains("at least 16")
        );
        assert!(
            Tagger::new(Some("")).is_ok(),
            "an empty REDACT_KEY means no key"
        );
    }

    #[test]
    fn two_values_never_share_a_tag() {
        let mut t = Tagger::new(Some("0123456789abcdef0123")).unwrap();
        let first = t.tag("ORG", "fabrikam");
        let hex = first
            .trim_start_matches("[ORG-")
            .trim_end_matches(']')
            .to_string();
        // Pretend another value already holds the tag `fabrikam` would get.
        let mut clash = Tagger::new(Some("0123456789abcdef0123")).unwrap();
        clash.used.insert(hex.clone());
        let second = clash.tag("ORG", "fabrikam");
        assert_ne!(second, first, "a taken tag was handed out again");
        assert_eq!(clash.tag("ORG", "fabrikam"), second, "same value, same tag");
    }

    fn only(files: &[std::path::PathBuf]) -> Result<pack::Loaded, String> {
        pack::load(&pack::Options {
            files: files.to_vec(),
            builtin: false,
            user: false,
            config: None,
            env_files: vec![],
        })
    }

    /// The built-in packs' output, with each tag's random hex shown as `…`: a
    /// random tag such as `[OBJECT-ID-a17946f0]` must not read as a leaked `7946`.
    fn azure(text: &str) -> String {
        let loaded = pack::load(&pack::Options {
            files: vec![],
            builtin: true,
            user: false,
            config: None,
            env_files: vec![],
        })
        .unwrap();
        let out = mask(
            text,
            &scan(text, &loaded).unwrap(),
            &mut Tagger::new(None).unwrap(),
        );
        blank_tags(&out)
    }

    fn blank_tags(out: &str) -> String {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(\[[A-Z][A-Z0-9-]*)-[0-9a-f]{8}\]").unwrap())
            .replace_all(out, "$1-…]")
            .into_owned()
    }

    /// A fresh folder for one test's files.
    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("redact-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn hides(text: &str, value: &str, label: &str) {
        let out = azure(text);
        assert!(!out.contains(value), "still shows {value}: {out}");
        assert!(
            out.contains(&format!("[{label}-")),
            "no [{label}-…] in: {out}"
        );
    }

    fn keeps(text: &str) {
        assert_eq!(azure(text), text);
    }

    const G: &str = "00000001-7b4d-4e8a-9c21-5d6e7f8a9b0c";

    #[test]
    fn ids_beside_their_names() {
        hides(&format!(r#"{{"tenantId": "{G}"}}"#), G, "TENANT-ID");
        hides(
            &format!("/subscriptions/{G}/resourceGroups/rg"),
            G,
            "SUBSCRIPTION-ID",
        );
        hides(
            &format!(r#"{{"id": "{G}", "isDefault": true}}"#),
            G,
            "SUBSCRIPTION-ID",
        );
        hides(&format!("export AZURE_CLIENT_ID={G}"), G, "APP-ID");
    }

    /// A fake key body, built at run time so no key-shaped string sits in the repo.
    fn body(n: usize) -> String {
        let abc = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
        (0..n)
            .map(|i| abc.as_bytes()[(i * 7 + 3) % abc.len()] as char)
            .collect()
    }

    #[test]
    fn git_log_and_config_hide_people() {
        let log = "commit abc123\nAuthor:     Jordan Quillfeather <jq@fabrikamq.example>\nAuthorDate: Mon Nov 10 2026\nCommit:     Morwenna Tregarthen <mt@fabrikamq.example>\n\n    Fix the build\n\n    Co-authored-by: Ellery Vandermolen <ev@fabrikamq.example>\n";
        let out = azure(log);
        for gone in ["Quillfeather", "Tregarthen", "Vandermolen", "@fabrikamq"] {
            assert!(!out.contains(gone), "still shows {gone}:\n{out}");
        }
        assert!(
            out.contains("Fix the build") && out.contains("commit abc123"),
            "{out}"
        );
        let cfg = "user.name=Jordan Quillfeather\nuser.email=jq@fabrikamq.example\ncore.editor=nvim\nremote.origin.url=git@github.com:o/r.git\n";
        let out = azure(cfg);
        assert!(
            !out.contains("Quillfeather") && !out.contains("jq@"),
            "{out}"
        );
        assert!(
            out.contains("core.editor=nvim") && out.contains("git@github.com"),
            "{out}"
        );
    }

    #[test]
    fn a_github_user_record() {
        let text = r#"{"login": "quillfeatherq", "id": 1, "html_url": "https://github.com/quillfeatherq", "repos_url": "https://api.github.com/users/quillfeatherq/repos", "name": "Jordan Quillfeather", "company": "Fabrikamq", "location": "Leeds", "email": "jq@fabrikamq.example", "public_repos": 12}"#;
        let out = azure(text);
        for gone in ["quillfeatherq", "Quillfeather", "Fabrikamq", "Leeds", "jq@"] {
            assert!(!out.contains(gone), "still shows {gone}:\n{out}");
        }
        assert!(
            out.contains("\"public_repos\": 12") && out.contains("api.github.com/users/"),
            "{out}"
        );
    }

    #[test]
    fn second_audit_gaps() {
        // A GitHub user record whose URLs hold braces, so `name` sits in a later record part.
        let gh = r#"{"login":"quillfeatherq","html_url":"https://github.com/quillfeatherq","following_url":"https://api.github.com/users/quillfeatherq/following{/other_user}","type":"User","user_view_type":"public","site_admin":false,"name":"Jordan Quillfeather","company":null,"public_repos":24}"#;
        let out = azure(gh);
        assert!(
            !out.contains("Quillfeather") && !out.contains("quillfeatherq"),
            "{out}"
        );
        // A variable with no isSecret field.
        let vg = r#"{"variables": {"GoogleAnalytics": {"value": "G-ABC123XYZ9"}, "webapp_pipeline_yaml_path": {"isSecret": false, "value": "pipelines\\bluefinq\\web.yml"}}}"#;
        let out = azure(vg);
        assert!(
            !out.contains("G-ABC123XYZ9") && !out.contains("bluefinq"),
            "{out}"
        );
        // directoryAlias, and an SSH clone URL on its own.
        let out = azure(r#"{"user": {"directoryAlias": "jquillq", "principalName": "x"}}"#);
        assert!(!out.contains("jquillq"), "{out}");
        let out = azure(r#"{"sshUrl": "git@ssh.dev.azure.com:v3/fabrikamq/Bluefinq/app"}"#);
        assert!(
            !out.contains("fabrikamq")
                && !out.contains("Bluefinq")
                && out.contains("git@ssh.dev.azure.com:v3/"),
            "{out}"
        );
    }

    #[test]
    fn pipeline_variable_group_values() {
        let text = r#"[{"id": 7, "name": "app-settings", "type": "Vsts", "variables": {
  "sit-app-client-id": {"isReadOnly": false, "isSecret": false, "value": "0000000c-7b4d-4e8a-9c21-5d6e7f8a9b0c"},
  "api-host": {"isSecret": false, "value": "bluefin-api.internal.fabrikamq.example"},
  "db-password": {"isSecret": true, "value": null}
}}]"#;
        let out = azure(text);
        assert!(
            !out.contains("0000000c-7b4d") && !out.contains("bluefin-api"),
            "{out}"
        );
        assert!(
            out.contains("\"sit-app-client-id\"")
                && out.contains("\"app-settings\"")
                && out.contains("null"),
            "{out}"
        );
    }

    #[test]
    fn azure_devops_userinfo_and_mail_address() {
        let repo = r#"{"name": "app", "remoteUrl": "https://fabrikamq@dev.azure.com/fabrikamq/Bluefinq/_git/app"}"#;
        let out = azure(repo);
        assert!(
            !out.contains("fabrikamq") && !out.contains("Bluefinq"),
            "{out}"
        );
        let user = r#"{"principalName": "jq@fabrikamq.example", "mailAddress": "jordan.q@fabrikamq.example", "displayName": "Jordan Quillfeather"}"#;
        let out = azure(user);
        assert!(
            !out.contains("jordan.q@") && !out.contains("Quillfeather"),
            "{out}"
        );
    }

    #[test]
    fn credentials_by_shape() {
        let jwt = format!(
            "ey{}.ey{}.{}",
            "J".to_owned() + &body(30),
            "J".to_owned() + &body(60),
            body(40)
        );
        let gh = format!("gh{}_{}", "p", body(36));
        let ant = format!("sk-{}-{}", "ant", body(40));
        let aws = format!("AK{}{}", "IA", body(16).to_uppercase());
        let pem = format!(
            "-----BEGIN {} KEY-----\n{}\n-----END {} KEY-----",
            "PRIVATE",
            body(64),
            "PRIVATE"
        );
        for (text, value) in [
            (
                format!(r#"{{"accessToken": "{jwt}", "tokenType": "Bearer"}}"#),
                jwt.clone(),
            ),
            (format!("Authorization: Bearer {}", body(40)), body(40)),
            (
                format!("git clone https://x:{gh}@github.com/o/r"),
                gh.clone(),
            ),
            (format!("key is {ant} ok"), ant.clone()),
            (format!("aws id {aws} here"), aws.clone()),
            (pem.clone(), body(64)),
            (
                format!("DefaultEndpointsProtocol=https;AccountKey={}==;", body(86)),
                body(86),
            ),
            (
                "postgres://app:hunter2pass@db.example.com/x".into(),
                "hunter2pass".into(),
            ),
        ] {
            let out = azure(&text);
            assert!(!out.contains(&value), "still shows a secret:\n{out}");
        }
        // `Bearer` and `true` are settings, not secrets.
        let out = azure(&format!(
            r#"{{"accessToken": "{jwt}", "tokenType": "Bearer"}}"#
        ));
        assert!(out.contains("\"Bearer\""), "{out}");
    }

    // Regressions from the independent review of 2026-11-14.

    #[test]
    fn overlapping_finds_hide_every_byte_either_found() {
        // named-secret stops at the comma; url-password covers the whole password.
        let text = r#"{"connection_string": "postgres://app:alpha1,bravo2zz@db-host:5432/x"}"#;
        let out = azure(text);
        assert!(
            !out.contains("alpha1") && !out.contains("bravo2zz"),
            "{out}"
        );
    }

    #[test]
    fn a_multiword_quoted_secret_is_hidden_whole() {
        for text in [
            r#"{"password": "correct horse battery staple"}"#,
            "password: 'correct horse battery staple'",
            "db:\n  password: correct horse battery staple\n  host: db-host\n",
            "PASSWORD=correct horse battery staple",
        ] {
            let out = azure(text);
            for w in ["correct", "horse", "battery", "staple"] {
                assert!(!out.contains(w), "still shows {w}: {out}");
            }
        }
        // The line after keeps its own content.
        let out = azure("password: correct horse battery\nhost: db-host\n");
        assert!(out.contains("host: db-host"), "{out}");
    }

    #[test]
    fn a_records_fields_count_whatever_their_order() {
        let sub = "0000000d-7b4d-4e8a-9c21-5d6e7f8a9b0c";
        for text in [
            // isDefault, then a nested user, then id and name.
            format!(
                r#"{{"isDefault": true, "user": {{"name": "x", "type": "user"}}, "id": "{sub}", "name": "Fabrikamq Prod"}}"#
            ),
            // id before the nested user, isDefault after it.
            format!(
                r#"{{"id": "{sub}", "name": "Fabrikamq Prod", "user": {{"name": "x", "type": "user"}}, "isDefault": true}}"#
            ),
            // a brace inside a string does not split the record.
            format!(
                r#"{{"id": "{sub}", "note": "a {{ brace", "isDefault": true, "name": "Fabrikamq Prod"}}"#
            ),
        ] {
            let out = azure(&text);
            assert!(!out.contains(sub) && !out.contains("Fabrikamq"), "{out}");
        }
    }

    #[test]
    fn credentials_by_name() {
        let secret = body(24);
        for text in [
            format!("export AZURE_DEVOPS_EXT_PAT={secret}"),
            format!(r#"{{"client_secret": "{secret}"}}"#),
            format!("password: {secret}"),
            format!("API_KEY=\"{secret}\""),
        ] {
            let out = azure(&text);
            assert!(!out.contains(&secret), "still shows a secret: {out}");
        }
        for kept in [
            r#""isSecret": false"#,
            "TOKEN=$AZURE_TOKEN",
            "token: <placeholder>",
        ] {
            assert_eq!(azure(kept), kept, "a non-secret was hidden");
        }
    }

    #[test]
    fn env_dump_values_but_not_settings() {
        let text = "AZURE_ORGANISATION=fabrikam-dev\nPORT=3000\nNODE_ENV=development\nexport PROJECT_NAME=\"Bluefinq Portal\"\n";
        let out = azure(text);
        assert!(
            !out.contains("fabrikam-dev") && !out.contains("Bluefinq"),
            "{out}"
        );
        assert!(
            out.contains("PORT=3000") && out.contains("NODE_ENV=development"),
            "{out}"
        );
    }

    #[test]
    fn az_ad_signed_in_user_leaves_nothing_identifying() {
        // The shape Microsoft Graph documents for /me, with fake values.
        let text = format!(
            r#"{{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users/$entity",
  "businessPhones": ["+44 20 7946 0123"],
  "companyName": "Fabrikamq Holdings",
  "displayName": "Jordan Quillfeather",
  "givenName": "Jordan",
  "id": "{G}",
  "jobTitle": "Senior Test Analyst",
  "mail": "jordan.q@fabrikamq.example",
  "mobilePhone": "07700 900123",
  "officeLocation": "Leeds Wellington Place",
  "preferredLanguage": "en-GB",
  "surname": "Quillfeather",
  "userPrincipalName": "jordan.q@fabrikamq.example"
}}"#
        );
        let out = azure(&text);
        for gone in [
            G,
            "Fabrikamq",
            "Quillfeather",
            "Jordan",
            "Senior Test",
            "jordan.q@",
            "7946",
            "900123",
            "Wellington",
        ] {
            assert!(!out.contains(gone), "still shows {gone}:\n{out}");
        }
        for kept in ["graph.microsoft.com", "en-GB", "\"jobTitle\""] {
            assert!(out.contains(kept), "lost {kept}:\n{out}");
        }
    }

    #[test]
    fn az_account_show_leaves_nothing_identifying() {
        let text = format!(
            r#"{{
  "environmentName": "AzureCloud",
  "homeTenantId": "{G}",
  "id": "{G}",
  "isDefault": true,
  "managedByTenants": [],
  "name": "Fabrikamq Production",
  "state": "Enabled",
  "tenantDefaultDomain": "fabrikamq.onmicrosoft.com",
  "tenantDisplayName": "Fabrikamq Holdings",
  "tenantId": "{G}",
  "user": {{
    "name": "jordan@fabrikamq.example",
    "type": "user"
  }}
}}"#
        );
        let out = azure(&text);
        for gone in [G, "Fabrikamq", "fabrikamq", "jordan@"] {
            assert!(!out.contains(gone), "still shows {gone}:\n{out}");
        }
        for kept in ["AzureCloud", "\"Enabled\"", "\"type\": \"user\""] {
            assert!(out.contains(kept), "lost {kept}:\n{out}");
        }
    }

    #[test]
    fn bare_and_public_ids_stay() {
        keeps(&format!("request {G} failed"));
        keeps(r#"{"appId": "04b07795-8ddb-461a-bbee-02f9e1bf7b46"}"#);
    }

    #[test]
    fn a_persons_ids_are_hidden_everywhere() {
        let person = "00000009-7b4d-4e8a-9c21-5d6e7f8a9b0c";
        let tenant = "0000000a-7b4d-4e8a-9c21-5d6e7f8a9b0c";
        let member = "0000000b-7b4d-4e8a-9c21-5d6e7f8a9b0c";
        // A work item's AssignedTo, then `az devops user list`, where the member's
        // outer `id` sits outside the record that names the user.
        let text = format!(
            r#"{{"System.AssignedTo": {{"_links": {{"avatar": {{"href": "https://x/a"}}}}, "descriptor": "aad.x", "displayName": "Jordan Quillfeather", "id": "{person}", "uniqueName": "jq@example.com"}}}}
{{"members": [{{"id": "{person}", "user": {{"originId": "{person}", "domain": "{tenant}", "principalName": "jq@example.com"}}}}]}}
{{"members": [{{"accessLevel": {{"licenseDisplayName": "Basic"}}, "id": "{member}", "lastAccessedDate": "2026-11-01T00:00:00Z"}}]}}"#
        );
        let out = azure(&text);
        assert!(
            !out.contains(person) && !out.contains(tenant) && !out.contains(member),
            "{out}"
        );
        assert_eq!(out.matches("[IDENTITY-ID-").count(), 5, "{out}");
        assert!(out.contains("\"Basic\""), "{out}");
    }

    #[test]
    fn people_then_everywhere() {
        let text = r#"{"displayName": "Jordan Quillfeather", "uniqueName": "jq@example.com"} later: @Jordan Quillfeather"#;
        let out = azure(text);
        assert!(!out.contains("Quillfeather"), "{out}");
        assert_eq!(out.matches("[PERSON-").count(), 2, "{out}");
    }

    #[test]
    fn devops_found_by_place() {
        let out = azure(
            "git clone https://dev.azure.com/fabrikamq/ZQX/_git/OrderPortal; cd C:\\zqx\\automation",
        );
        assert!(
            !out.contains("fabrikamq")
                && !out.contains("ZQX")
                && !out.contains("zqx")
                && !out.contains("OrderPortal"),
            "{out}"
        );
        // a stray lower-case `org` is not remembered as a name
        let out = azure("https://dev.azure.com/org/proj/_git/r see example.org");
        assert!(out.ends_with("see example.org"), "{out}");
    }

    #[test]
    fn own_hosts_not_public_ones() {
        hides(
            "https://bluefin-uat.crm11.dynamics.com/api",
            "bluefin-uat",
            "DATAVERSE-ENV",
        );
        hides(
            "https://kv-bluefin.vault.azure.net/secrets/x",
            "kv-bluefin",
            "AZURE-RESOURCE",
        );
        keeps("see https://portal.azure.com and https://make.powerapps.com");
    }

    #[test]
    fn a_word_list_file() {
        let path =
            std::env::temp_dir().join(format!("redact-test-{}-customers.txt", std::process::id()));
        std::fs::write(&path, "# a note\nNorthwind Traders\nContoso Pharma\n").unwrap();
        let loaded = only(std::slice::from_ref(&path)).unwrap();
        let text = "Northwind traders and CONTOSO PHARMA, not Contosoville";
        let out = mask(
            text,
            &scan(text, &loaded).unwrap(),
            &mut Tagger::new(None).unwrap(),
        );
        std::fs::remove_file(&path).unwrap();
        assert!(
            !out.to_lowercase().contains("northwind") && !out.to_lowercase().contains("pharma"),
            "{out}"
        );
        assert!(out.contains("Contosoville"), "{out}");
    }

    #[test]
    fn a_bad_pack_is_an_error_naming_it() {
        let path =
            std::env::temp_dir().join(format!("redact-test-{}-bad.toml", std::process::id()));
        std::fs::write(&path, "schema_version = 1\nid = \"x\"\n[[rules]]\nid = \"r\"\nregex = \"a(b)\"\nsecretGroup = 2\n").unwrap();
        let err = only(std::slice::from_ref(&path)).err().unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(err.contains("bad.toml") && err.contains("group 2"), "{err}");
    }

    #[test]
    fn imports_resolve_beside_the_file_and_nest() {
        let d = tmp("imports");
        std::fs::create_dir_all(d.join("work/lists")).unwrap();
        std::fs::write(d.join("config.toml"), "import = [\"work/more.toml\"]\n").unwrap();
        std::fs::write(d.join("work/more.toml"), "import = [\"lists\"]\n").unwrap();
        std::fs::write(d.join("work/lists/customers.txt"), "Northwind Traders\n").unwrap();
        let loaded = only(&[d.join("config.toml")]).unwrap();
        let text = "ship to Northwind Traders";
        let out = mask(
            text,
            &scan(text, &loaded).unwrap(),
            &mut Tagger::new(None).unwrap(),
        );
        let kinds: Vec<&str> = loaded.sources.iter().map(|s| s.kind).collect();
        std::fs::remove_dir_all(&d).unwrap();
        assert!(out.contains("[CUSTOMERS-"), "{out}");
        assert_eq!(kinds, ["config", "config", "folder", "words"]);
        assert!(loaded.sources[3].via.as_deref().unwrap().ends_with("lists"));
    }

    #[test]
    fn an_import_loop_is_an_error() {
        let d = tmp("loop");
        std::fs::write(d.join("a.toml"), "import = [\"b.toml\"]\n").unwrap();
        std::fs::write(d.join("b.toml"), "import = [\"a.toml\"]\n").unwrap();
        let err = only(&[d.join("a.toml")]).err().unwrap();
        std::fs::remove_dir_all(&d).unwrap();
        assert!(
            err.contains("import loop") && err.contains("a.toml -> ") && err.contains("b.toml"),
            "{err}"
        );
    }

    #[test]
    fn a_missing_import_names_who_asked() {
        let d = tmp("missing");
        std::fs::write(d.join("config.toml"), "import = [\"gone.txt\"]\n").unwrap();
        let err = only(&[d.join("config.toml")]).err().unwrap();
        std::fs::remove_dir_all(&d).unwrap();
        assert!(
            err.contains("gone.txt") && err.contains("imported by"),
            "{err}"
        );
    }

    #[test]
    fn a_config_typo_is_an_error() {
        let d = tmp("typo");
        std::fs::write(d.join("config.toml"), "imports = [\"x.txt\"]\n").unwrap();
        let err = only(&[d.join("config.toml")]).err().unwrap();
        std::fs::remove_dir_all(&d).unwrap();
        assert!(err.contains("imports"), "{err}");
    }

    // Regressions from the second independent review (batch 1: the engine).

    /// Masks `text` with the files in a fresh folder, tags blanked.
    fn with_files(name: &str, files: &[(&str, &[u8])], text: &str) -> String {
        let d = tmp(name);
        for (path, body) in files {
            let p = d.join(path);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, body).unwrap();
        }
        let loaded = only(std::slice::from_ref(&d)).unwrap();
        let out = mask(
            text,
            &scan(text, &loaded).unwrap(),
            &mut Tagger::new(None).unwrap(),
        );
        std::fs::remove_dir_all(&d).unwrap();
        blank_tags(&out)
    }

    #[test]
    fn a_word_beside_unicode_punctuation_or_underscores() {
        let list: &[(&str, &[u8])] = &[("customers.txt", b"Contoso\n")];
        for text in [
            "Contoso\u{2019}s deal",
            "Contoso\u{2014}Fabrikam",
            "\u{ab}Contoso\u{bb}",
            "rg_contoso_prod",
            "CONTOSO_API_KEY",
        ] {
            let out = with_files("edges", list, text);
            assert!(
                !out.to_lowercase().contains("contoso"),
                "still shows: {out}"
            );
        }
        assert!(with_files("edges2", list, "Contosoville").contains("Contosoville"));
    }

    #[test]
    fn a_word_list_with_a_bom_and_notes() {
        let list: &[(&str, &[u8])] = &[(
            "customers.txt",
            b"\xef\xbb\xbfContoso # main customer\nFabrikam\n",
        )];
        let out = with_files("bom", list, "Contoso and Fabrikam");
        assert!(
            !out.contains("Contoso") && !out.contains("Fabrikam"),
            "{out}"
        );
    }

    #[test]
    fn crlf_does_not_stick_to_remembered_values() {
        let out = azure("user.name=Jordan Quillfeather\r\nlater Jordan Quillfeather here\r\n");
        assert!(!out.contains("Quillfeather"), "{out}");
        assert!(out.contains("\r\nlater"), "line endings changed: {out:?}");
    }

    #[test]
    fn a_label_never_shows_a_listed_word() {
        let files: &[(&str, &[u8])] = &[("customers.txt", b"Contoso\n")];
        let d = tmp("labels");
        for (p, b) in files {
            std::fs::write(d.join(p), b).unwrap();
        }
        std::fs::write(d.join("x.env"), "CONTOSO_TOKEN=zq-secret-value-123\n").unwrap();
        let loaded = pack::load(&pack::Options {
            files: vec![d.join("customers.txt")],
            builtin: false,
            user: false,
            config: None,
            env_files: vec![d.join("x.env")],
        })
        .unwrap();
        let text = "the token is zq-secret-value-123";
        let out = mask(
            text,
            &scan(text, &loaded).unwrap(),
            &mut Tagger::new(None).unwrap(),
        );
        std::fs::remove_dir_all(&d).unwrap();
        assert!(
            !out.to_lowercase().contains("contoso") && !out.contains("zq-secret"),
            "{out}"
        );
    }

    #[test]
    fn a_packs_folder_loads_subfolders_and_any_case() {
        let files: &[(&str, &[u8])] = &[
            ("clients/Clients.TXT", b"Northwindq\n"),
            ("notes.list", b"x\n"),
        ];
        let out = with_files("folders", files, "ship to Northwindq");
        assert!(!out.contains("Northwindq"), "{out}");
        let d = tmp("folders2");
        std::fs::write(d.join("notes.list"), "x\n").unwrap();
        let loaded = only(std::slice::from_ref(&d)).unwrap();
        std::fs::remove_dir_all(&d).unwrap();
        assert!(
            loaded.sources[0].detail.contains("skipped"),
            "{}",
            loaded.sources[0].detail
        );
    }
}
