//! What a placeholder looks like: `[LABEL-<8 hex>]`, such as `[SECRET-a1b2c3d4]`.
//!
//! Every label leaves the binary in this shape: a pack's own label is checked
//! when the pack loads, a `[labels]` rename when the config loads, and a rule id
//! or file name is folded to fit. The Claude Code mod reads the same shape
//! (`TAG` in claude-plugin/hooks/vault.ts), and integration.test.mjs checks
//! that the two agree.

use regex::Regex;
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

#[cfg(test)]
mod tests {
    use super::*;

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
