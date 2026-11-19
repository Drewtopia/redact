//! Runs the `[[rules.tests]]` each rule carries in its pack.
//!
//! - **Exact:** a rule alone hides exactly the values a test expects, no more and
//!   no less, so a partial or an extra find fails.
//! - **Layouts:** a test whose input is just its one value also places that value
//!   in each of `LAYOUTS`, where the rule must still hide it, and straight after a
//!   letter, where the rule must not hide part of the longer word.
//! - **Precedence:** with every built-in pack on, such a value is hidden under its
//!   own rule, so a generic rule cannot hide a miss.
//! - **Coverage:** every built-in rule has a test that hides something.

use crate::pack::{self, Loaded, Pack};
use crate::scan::scan;

fn load(files: &[std::path::PathBuf], builtin: bool) -> Result<Loaded, String> {
    pack::load(&pack::Options {
        files: files.to_vec(),
        builtin,
        user: false,
        config: None,
        env_files: vec![],
        command: None,
        cwd: None,
        host: None,
    })
}

/// Where a value turns up in tool output. `{v}` is the value.
const LAYOUTS: &[(&str, &str)] = &[
    ("on a line of its own", "first\n{v}\nlast"),
    ("after a literal \\n", "line\\n{v}"),
    ("in double quotes", "\"{v}\""),
    ("in single quotes", "'{v}'"),
    ("after =", "x={v}"),
    ("after a colon", "x: {v}"),
    ("as a JSON value", "{\"x\": \"{v}\"}"),
    ("as a YAML value", "x:\n  y: {v}\n"),
];

/// A pack holding only `rule`, so every span the scan returns is the rule's own.
fn alone(pack: &Pack, rule: &pack::Rule) -> Loaded {
    Loaded {
        packs: vec![Pack {
            rules: vec![rule.clone()],
            ..pack.clone()
        }],
        ..Default::default()
    }
}

/// The distinct values hidden in `text`, sorted.
fn hidden(text: &str, loaded: &Loaded) -> Vec<String> {
    let mut v: Vec<String> = scan(text, loaded)
        .unwrap()
        .iter()
        .map(|s| text[s.start..s.end].to_string())
        .collect();
    v.sort();
    v.dedup();
    v
}

/// The values a test expects; the loader refuses a test without `expect`.
fn expect(t: &pack::RuleTest) -> &[String] {
    t.expect.as_deref().unwrap_or_default()
}

/// Whether a test's input is just the one value it expects.
fn bare(t: &pack::RuleTest) -> bool {
    expect(t) == [t.input.as_str()]
}

/// What is wrong with `rule`'s tests, one line each, starting `pack:rule `.
fn failures(pack: &Pack, rule: &pack::Rule) -> Vec<String> {
    let id = format!("{}:{}", pack.id, rule.id);
    let one = alone(pack, rule);
    let mut out = Vec::new();
    if rule.matrix && !rule.tests.iter().any(bare) {
        out.push(format!(
            "{id} has no test whose input is its bare value: add one, or set matrix = false"
        ));
    }
    for t in &rule.tests {
        let mut want = expect(t).to_vec();
        want.sort();
        want.dedup();
        let got = hidden(&t.input, &one);
        if got != want {
            out.push(format!(
                "{id} in {:?}: expected {want:?}, hid {got:?}",
                t.input
            ));
        }
        if !rule.matrix || !bare(t) {
            continue;
        }
        let v = &t.input;
        for (name, layout) in LAYOUTS {
            let text = layout.replace("{v}", v);
            let got = hidden(&text, &one);
            if got != [v.clone()] {
                out.push(format!("{id} {name}: {text:?} hid {got:?}"));
            }
        }
        // Part of a longer word is never hidden; all of it may be.
        let word = format!("a{v}");
        let got = hidden(&word, &one);
        if !(got.is_empty() || got == [word.clone()]) {
            out.push(format!("{id} after a letter: {word:?} hid {got:?}"));
        }
    }
    out
}

fn pack_file(name: &str, text: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("redact-rt-{}-{name}.toml", std::process::id()));
    std::fs::write(&p, text).unwrap();
    p
}

#[test]
fn a_rule_carries_its_tests() {
    let p = pack_file(
        "loads",
        "schema_version = 1\nid = \"x\"\n[[rules]]\nid = \"r\"\nregex = 'k([0-9]+)'\nsecretGroup = 1\n\
         [[rules.tests]]\ninput = \"k123\"\nexpect = [\"123\"]\n\
         [[rules.tests]]\ninput = \"k\"\nexpect = []\n",
    );
    let loaded = load(std::slice::from_ref(&p), false).unwrap();
    let tests = &loaded.packs[0].rules[0].tests;
    assert_eq!(tests.len(), 2);
    assert_eq!(tests[0].input, "k123");
    assert_eq!(expect(&tests[0]), ["123"]);
    assert!(expect(&tests[1]).is_empty());
}

#[test]
fn a_test_with_no_expect_or_an_unknown_field_is_an_error() {
    for (name, body) in [
        ("noexpect", "input = \"k1\"\n"),
        ("typo", "input = \"k1\"\nexpect = []\nexpected = []\n"),
    ] {
        let p = pack_file(
            name,
            &format!(
                "schema_version = 1\nid = \"x\"\n[[rules]]\nid = \"r\"\nregex = 'k'\n[[rules.tests]]\n{body}"
            ),
        );
        let err = load(std::slice::from_ref(&p), false).err().unwrap();
        assert!(err.contains(&format!("{name}.toml")), "{name}: {err}");
        if name == "noexpect" {
            assert!(err.contains("rule r "), "{err}");
        }
    }
}

#[test]
fn the_runner_reports_wrong_partial_and_missed_layouts() {
    let p = pack_file(
        "runner",
        r#"schema_version = 1
id = "x"

[[rules]]
id = "wrong"
regex = 'k([0-9]+)'
secretGroup = 1
[[rules.tests]]
input = "k123"
expect = ["12"]

[[rules]]
id = "partial"
regex = '[0-9]{3}'
[[rules.tests]]
input = "123"
expect = ["123"]

[[rules]]
id = "no-bare"
regex = 'k([0-9]+)'
secretGroup = 1
[[rules.tests]]
input = "k1"
expect = ["1"]

[[rules]]
id = "opted-out"
regex = 'k([0-9]+)'
secretGroup = 1
matrix = false
[[rules.tests]]
input = "k1"
expect = ["1"]

[[rules]]
id = "lines-only"
regex = '(?m)^tok_[a-z]{4}$'
[[rules.tests]]
input = "tok_abcd"
expect = ["tok_abcd"]
"#,
    );
    let loaded = load(std::slice::from_ref(&p), false).unwrap();
    let fails: Vec<String> = loaded.packs[0]
        .rules
        .iter()
        .flat_map(|r| failures(&loaded.packs[0], r))
        .collect();
    let has = |rule: &str, what: &str| {
        assert!(
            fails
                .iter()
                .any(|f| f.starts_with(&format!("x:{rule} ")) && f.contains(what)),
            "no {rule} failure mentioning {what:?} in {fails:#?}"
        )
    };
    has("wrong", "hid [\"123\"]");
    has("partial", "after a letter");
    has("lines-only", "in double quotes");
    has("no-bare", "bare value");
    assert!(
        !fails.iter().any(|f| f.starts_with("x:opted-out ")),
        "{fails:#?}"
    );
}

/// Every built-in pack, switched-off ones (`pii`, `work`) included.
fn builtin() -> Vec<Pack> {
    let l = load(&[], true).unwrap();
    l.packs.into_iter().chain(l.off).collect()
}

/// Layouts a built-in rule is known to fail, and why: `(pack:rule, layout, why)`.
/// A known failure that starts passing fails the test too, so this list cannot
/// go stale. Betterleaks keeps the same kind of list (`intendedOverrides`).
const KNOWN: &[(&str, &str, &str)] = &[
    // Their regex starts with `\b` or lists no `\n` delimiter, and #61's fix
    // did not reach them: #74.
    ("pii:mac-address", "after a literal \\n", "#74"),
    ("identity:email", "after a literal \\n", "#74"),
    // A token never starts after a backslash, so `\n` escapes are not hidden
    // with it; and `=` is part of a token, so `x=` is hidden with the value: #56.
    ("credentials:random-token", "after a literal \\n", "#56"),
    ("credentials:random-token", "after =", "#56"),
    // On purpose: digits are a card number whatever letters lead into them
    // (`ORD4111…`), since hiding a few extra digits is the safe side.
    ("pii:card-number", "after a letter", "intended"),
    // `v1.2.3.4` has `1.2.3.4` hidden. Barring a letter before it would also
    // miss one after a literal `\n`; the shared delimiter in #74 settles both.
    ("pii:ipv4", "after a letter", "#74"),
];

#[test]
fn every_built_in_rule_passes_its_tests() {
    let mut fails = Vec::new();
    let mut seen = Vec::new();
    for p in builtin() {
        for r in &p.rules {
            let id = format!("{}:{}", p.id, r.id);
            if !r.tests.iter().any(|t| !expect(t).is_empty()) {
                fails.push(format!("{id} has no test that hides a value"));
            }
            for f in failures(&p, r) {
                match KNOWN
                    .iter()
                    .find(|(k, layout, _)| *k == id && f.starts_with(&format!("{id} {layout}:")))
                {
                    Some(k) => seen.push(k),
                    None => fails.push(f),
                }
            }
        }
    }
    for k in KNOWN.iter().filter(|k| !seen.contains(k)) {
        fails.push(format!("{} {} now passes: take it off KNOWN", k.0, k.1));
    }
    assert!(
        fails.is_empty(),
        "{} rule test failures:\n{}",
        fails.len(),
        fails.join("\n")
    );
}

/// Values a broader rule claims first, and why that is fine:
/// `(pack:rule, the rule that hides its value, why)`. Like `KNOWN`, an entry
/// that stops happening fails the test.
const OVERLAPS: &[(&str, &str, &str)] = &[
    // The name before the value says secret too, and that rule starts sooner.
    (
        "credentials:bearer",
        "credentials:named-secret",
        "Authorization: names it",
    ),
    (
        "credentials:named-secret-yaml",
        "credentials:named-secret",
        "password: names it",
    ),
    (
        "credentials:secret-flag",
        "credentials:named-secret",
        "--client-secret= names it",
    ),
    // `pkgs.dev.azure.com/org` holds `dev.azure.com/org`.
    (
        "work:ado-org-artifacts",
        "work:ado-org",
        "same org, same label",
    ),
    // A `+1 (555) …` phone after `phone:` is an international number too.
    (
        "pii:phone-named",
        "pii:phone-international",
        "same number, same label",
    ),
];

#[test]
fn with_every_pack_on_a_value_is_hidden_by_its_own_rule() {
    let packs = builtin();
    let all = Loaded {
        packs: packs.clone(),
        ..Default::default()
    };
    let mut fails = Vec::new();
    let mut seen = Vec::new();
    for p in &packs {
        for r in &p.rules {
            let id = format!("{}:{}", p.id, r.id);
            for t in &r.tests {
                let spans = scan(&t.input, &all).unwrap();
                for v in expect(t) {
                    let at = t.input.find(v.as_str()).unwrap();
                    let by: Vec<String> = spans
                        .iter()
                        .filter(|s| s.start <= at && at + v.len() <= s.end)
                        .map(|s| format!("{}:{}", s.pack, s.rule))
                        .collect();
                    match OVERLAPS.iter().find(|o| o.0 == id && by == [o.1]) {
                        Some(o) => seen.push(o),
                        None if by != [id.clone()] => {
                            fails.push(format!("{id} {:?}: {v:?} hidden by {by:?}", t.input))
                        }
                        None => {}
                    }
                }
            }
        }
    }
    for o in OVERLAPS.iter().filter(|o| !seen.contains(o)) {
        fails.push(format!(
            "{} is no longer hidden by {}: take it off OVERLAPS",
            o.0, o.1
        ));
    }
    assert!(fails.is_empty(), "{}", fails.join("\n"));
}
