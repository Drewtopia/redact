//! What a placeholder looks like: `[LABEL-<8 hex>]`, such as `[SECRET-a1b2c3d4]`.
//!
//! Every label leaves the binary in this shape: a pack's own label is checked
//! when the pack loads, a `[labels]` rename when the config loads, and a rule id
//! or file name is folded to fit. The Claude Code mod reads the same shape
//! (`TAG` in claude-plugin/hooks/vault.ts), and integration.test.mjs checks
//! that the two agree.
//!
//! A name a span shows (label, rule id, pack id) can itself hold a hidden
//! value, so `clean_names` turns such a name into `VALUE` before it shows in a
//! placeholder, `--json` or `--explain`.

use crate::scan::Span;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

/// A rule's label when its pack gives none.
pub const SECRET: &str = "SECRET";
/// Every label in `[labels] style = "generic"`, and a name that folds to nothing.
pub const HIDDEN: &str = "HIDDEN";
/// A name (label, rule id, pack id) that holds something being hidden.
pub const VALUE: &str = "VALUE";
/// Kept for the Claude Code mod: it marks a placeholder read back from a file.
const LITERAL: &str = "LITERAL";

/// A label or name as labels match: upper case, `_` and spaces as `-`, so
/// `acme_org` finds `ACME_ORG`.
pub fn of(name: &str) -> String {
    name.trim().to_uppercase().replace(['_', ' '], "-")
}

/// A label someone wrote, in a pack or in `[labels]`, as it goes in placeholders.
/// An error says what a label may be.
pub fn check(label: &str) -> Result<String, String> {
    static RE: OnceLock<Regex> = OnceLock::new();
    let shape =
        RE.get_or_init(|| Regex::new(r"^[A-Za-z][A-Za-z0-9]*(?:[-_][A-Za-z0-9]+)*$").unwrap());
    let out = of(label);
    if !shape.is_match(label) || out == LITERAL {
        return Err(
            "a label is letters and digits, starts with a letter, may join words with one - or _, and is not LITERAL"
                .into(),
        );
    }
    Ok(out)
}

/// A rule id or list name as a label: `v1.2_key` is `V1-2-KEY`, `123-customers`
/// is `CUSTOMERS`. The Claude Code mod folds an older binary's labels the same way.
pub fn fold(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_uppercase());
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
    }
    let out = out.trim_start_matches(|c: char| c.is_ascii_digit() || c == '-');
    match out.trim_end_matches('-') {
        "" => HIDDEN.into(),
        LITERAL => format!("{LITERAL}-LIST"),
        t => t.into(),
    }
}

/// A placeholder this tool or the mod wrote, such as `[SECRET-a1b2c3d4]`.
pub fn is_tag(v: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\[[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)*-[0-9a-f]{8}\]$").unwrap())
        .is_match(v)
}

/// Lower case with `-`, `_` and spaces folded together, to compare names and values.
fn key(s: &str) -> String {
    s.to_lowercase().replace(['_', ' '], "-")
}

/// Makes each span's names safe to show, and records its kind in `Span.was`.
///
/// A user pack's label, a pack id, or a word list's rule name can be a key or
/// file name (`CONTOSO_TOKEN`, `contoso.txt`), so it can hold something being
/// hidden: one of `words` (listed or remembered), or any value a span hides in
/// `text`. Such a name becomes VALUE, in the placeholder and in --json and
/// --explain alike. Only values short enough to fit inside a name are worth
/// checking. `kinds` maps `pack:rule` to the label before `[labels]` changed it.
pub fn clean_names<'a>(
    spans: &mut [Span],
    text: &str,
    words: impl IntoIterator<Item = &'a str>,
    kinds: &HashMap<String, String>,
) {
    let mut hidden: HashSet<String> = words.into_iter().map(key).collect();
    let longest = spans
        .iter()
        .map(|s| s.label.len().max(s.rule.len()).max(s.pack.len()))
        .max()
        .unwrap_or(0);
    hidden.extend(
        spans
            .iter()
            .filter(|s| s.end - s.start <= longest)
            .map(|s| key(&text[s.start..s.end])),
    );
    hidden.retain(|w| w.chars().count() >= 3);
    let mut safe: HashMap<String, String> = HashMap::new();
    let mut clean = |name: &str| -> String {
        safe.entry(name.to_string())
            .or_insert_with(|| {
                let folded = key(name);
                if hidden.iter().any(|w| folded.contains(w.as_str())) {
                    VALUE.to_string()
                } else {
                    name.to_string()
                }
            })
            .clone()
    };
    for s in spans {
        s.was = kinds
            .get(&format!("{}:{}", s.pack, s.rule))
            .map(|k| clean(k));
        s.label = clean(&s.label);
        s.rule = clean(&s.rule);
        s.pack = clean(&s.pack);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span(start: usize, end: usize, label: &str, pack: &str, rule: &str) -> Span {
        Span {
            start,
            end,
            label: label.into(),
            pack: pack.into(),
            rule: rule.into(),
            was: None,
        }
    }

    #[test]
    fn a_name_holding_a_hidden_value_reads_value() {
        let text = "key zuvio1 id ab from acme, cd";
        let mut spans = vec![
            // The rule id holds the value this span hides.
            span(4, 10, "ID", "p", "zuvio1-key"),
            // `ab` is too short to check, so a name holding it stays.
            span(14, 16, "LABS", "p", "tag"),
            // The pack id holds a listed word, in another case and spelling.
            span(22, 26, "WORDLIST", "words", "Acme_List"),
            // The rule id holds a listed word that is not in the text.
            span(28, 30, "ID", "p", "kepler-ids"),
        ];
        let kinds = HashMap::from([
            ("p:zuvio1-key".to_string(), "KEY".to_string()),
            ("p:tag".to_string(), "ACME".to_string()),
        ]);
        clean_names(&mut spans, text, ["acme", "kepler"], &kinds);
        let seen: Vec<_> = spans
            .iter()
            .map(|s| {
                (
                    s.label.as_str(),
                    s.pack.as_str(),
                    s.rule.as_str(),
                    s.was.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            seen,
            [
                ("ID", "p", "VALUE", Some("KEY")),
                ("LABS", "p", "tag", Some("VALUE")),
                ("WORDLIST", "words", "VALUE", None),
                ("ID", "p", "VALUE", None),
            ]
        );
    }

    #[test]
    fn a_written_label_is_checked_and_upper_cased() {
        assert_eq!(check("gh_token").unwrap(), "GH-TOKEN");
        assert_eq!(check("Customer").unwrap(), "CUSTOMER");
        for bad in [
            "1KEY", "LITERAL", "literal", "a b", "A__B", "A-_B", "KEY-", "my.label", "",
        ] {
            assert!(check(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_name_folds_into_a_label() {
        assert_eq!(fold("v1.2_key"), "V1-2-KEY");
        assert_eq!(fold("123-customers"), "CUSTOMERS");
        assert_eq!(fold("..."), "HIDDEN");
        assert_eq!(fold("literal"), "LITERAL-LIST");
    }

    #[test]
    fn every_label_makes_a_tag() {
        for name in ["v1.2_key", "123-customers", "...", "literal", "a--b"] {
            assert!(is_tag(&format!("[{}-a1b2c3d4]", fold(name))), "{name}");
        }
        assert!(is_tag(&format!(
            "[{}-a1b2c3d4]",
            check("gh_token").unwrap()
        )));
        // The mod's shape: no empty word between dashes.
        for bad in [
            "[A--B-a1b2c3d4]",
            "[-A-a1b2c3d4]",
            "[A-A1B2C3D4]",
            "[A-a1b2c3d]",
        ] {
            assert!(!is_tag(bad), "{bad}");
        }
    }
}
