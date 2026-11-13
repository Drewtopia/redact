//! Finding the parts of a text to hide, and swapping them for placeholders.

use crate::pack::{Loaded, Remember};
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

/// The text between braces: one JSON record's own fields, whatever their order.
fn records(text: &str) -> impl Iterator<Item = (usize, &str)> {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"[^{}]+").unwrap())
        .find_iter(text)
        .map(|m| (m.start(), m.as_str()))
}

pub fn scan(text: &str, loaded: &Loaded) -> Result<Vec<Span>, String> {
    // Keywords are a cheap test that a pack or rule could match at all.
    let low = text.to_lowercase();
    let has = |keys: &[String]| keys.is_empty() || keys.iter().any(|k| low.contains(k.as_str()));

    let mut spans = Vec::new();
    let mut words: Vec<Word> = Vec::new();

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
                Some(w) => records(text).filter(|(_, seg)| w.is_match(seg)).collect(),
            };
            for (offset, seg) in segments {
                for caps in rule.re.captures_iter(seg) {
                    let Some(m) = caps.get(rule.group) else {
                        continue;
                    };
                    if m.is_empty() || pack.allow.contains(&m.as_str().to_lowercase()) {
                        continue;
                    }
                    spans.push(Span {
                        start: offset + m.start(),
                        end: offset + m.end(),
                        label: rule.label.clone(),
                        pack: pack.id.clone(),
                        rule: rule.id.clone(),
                    });
                    let keep = match rule.remember {
                        Remember::No => false,
                        Remember::Distinctive => distinctive(m.as_str()),
                        Remember::Any => chosen_name(m.as_str()),
                    };
                    if keep {
                        words.push(Word {
                            text: m.as_str().to_string(),
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
    spans.extend(find_words(text, words)?);
    Ok(merge(spans))
}

/// Every remembered value and listed word, as a whole word, in any case.
fn find_words(text: &str, mut words: Vec<Word>) -> Result<Vec<Span>, String> {
    if words.is_empty() {
        return Ok(Vec::new());
    }
    // Longest first, so `Fabrikam Holdings` wins over `Fabrikam`.
    words.sort_by_key(|w| std::cmp::Reverse(w.text.len()));
    words.dedup_by(|a, b| a.text.to_lowercase() == b.text.to_lowercase());
    let alt = words
        .iter()
        .map(|w| regex::escape(&w.text))
        .collect::<Vec<_>>()
        .join("|");
    let re = Regex::new(&format!(r"(?i)\b(?:{alt})\b"))
        .map_err(|e| format!("word list too large to match: {e}"))?;
    Ok(re
        .find_iter(text)
        .map(|m| {
            let found = m.as_str().to_lowercase();
            // A match the case-folding could not tie back to its word still gets hidden.
            let w = words.iter().find(|w| w.text.to_lowercase() == found);
            Span {
                start: m.start(),
                end: m.end(),
                label: w.map_or("WORD".into(), |w| w.label.clone()),
                pack: w.map_or("words".into(), |w| w.pack.clone()),
                rule: w.map_or("words".into(), |w| w.rule.clone()),
            }
        })
        .collect())
}

/// Sorted, with overlaps removed: the earliest, then longest, span wins.
fn merge(mut spans: Vec<Span>) -> Vec<Span> {
    spans.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
    let mut out: Vec<Span> = Vec::new();
    for s in spans {
        if out.last().is_none_or(|l| s.start >= l.end) {
            out.push(s);
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

    fn azure(text: &str) -> String {
        let loaded = pack::load(&pack::Options {
            files: vec![],
            builtin: true,
            user: false,
            config: None,
            env_files: vec![],
        })
        .unwrap();
        mask(
            text,
            &scan(text, &loaded).unwrap(),
            &mut Tagger::new(None).unwrap(),
        )
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
}
