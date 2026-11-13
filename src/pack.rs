//! Loading packs (.toml rule files) and word lists (.txt, one word per line).

use regex::Regex;
use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Packs compiled into the binary, so `redact` works with no config at all.
const BUILTIN: &[(&str, &str)] = &[("azure", include_str!("../packs/azure.toml"))];

/// Whether a hidden value is also hidden wherever else it appears in the text.
#[derive(Deserialize, Default, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Remember {
    #[default]
    No,
    /// Only a value that reads as a name: a space, `-_.`, a digit, or an inner capital.
    Distinctive,
    /// Any value with a capital or of 5+ characters (not a stray `org` or `proj`).
    Any,
}

// The file shapes, exactly as written in TOML. `deny_unknown_fields` turns a typo
// (`secret_group` for `secretGroup`) into an error instead of a silently ignored key.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PackFile {
    schema_version: u32,
    id: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    keywords: Vec<String>,
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    rules: Vec<RuleFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct RuleFile {
    id: String,
    #[serde(default)]
    description: String,
    regex: String,
    #[serde(default)]
    secret_group: usize,
    label: Option<String>,
    within: Option<String>,
    #[serde(default)]
    remember: Remember,
    #[serde(default)]
    keywords: Vec<String>,
}

// The compiled forms the scanner uses.
pub struct Rule {
    pub id: String,
    pub description: String,
    pub re: Regex,
    pub group: usize,
    pub label: String,
    pub within: Option<Regex>,
    pub remember: Remember,
    pub keywords: Vec<String>,
}

pub struct Pack {
    pub id: String,
    pub description: String,
    pub source: String,
    pub keywords: Vec<String>,
    pub allow: HashSet<String>,
    pub rules: Vec<Rule>,
}

pub struct WordList {
    pub label: String,
    pub source: String,
    pub words: Vec<String>,
}

#[derive(Default)]
pub struct Loaded {
    pub packs: Vec<Pack>,
    pub words: Vec<WordList>,
    /// Every file that loaded, in load order: what `redact config ls` prints.
    pub sources: Vec<Source>,
}

pub struct Source {
    pub kind: &'static str,
    pub path: String,
    pub detail: String,
    pub via: Option<String>,
}

/// Where to load from. `config` replaces the default `~/.config/redact/config.toml`.
pub struct Options {
    pub files: Vec<PathBuf>,
    pub builtin: bool,
    pub user: bool,
    pub config: Option<PathBuf>,
}

/// A config file lists more files to load (packs, word lists, folders of either,
/// other config files; paths are relative to the file that names them), and the
/// environment variables whose values to hide.
///
/// `env` is how redact works with fnox, mise or anything else that sets
/// variables, without reading their files: `env = ["WORK_*"]` hides whatever
/// the `WORK_` variables hold when redact runs, e.g. under `fnox exec -- redact`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    #[serde(default)]
    import: Vec<String>,
    #[serde(default)]
    env: Vec<String>,
}

/// The variables an `env` list names: an exact name, or a prefix ending in `*`.
/// Each value is a word, or a list with one per line; the variable name is the label.
fn env_words(
    patterns: &[String],
    vars: impl Iterator<Item = (String, String)>,
) -> (Vec<WordList>, Vec<String>) {
    let mut lists: Vec<WordList> = vars
        .filter(|(name, _)| patterns.iter().any(|p| glob(p, name)))
        .map(|(name, value)| WordList {
            label: label_of(&name),
            source: format!("${name}"),
            words: value
                .lines()
                .map(str::trim)
                .filter(|l| l.chars().count() >= 3 && !l.starts_with('#'))
                .map(String::from)
                .collect(),
        })
        .collect();
    lists.sort_by(|a, b| a.label.cmp(&b.label));
    // An exact name that is not set: shown in `config ls`, so a missing hook is visible.
    let missing = patterns
        .iter()
        .filter(|p| !p.contains('*') && !lists.iter().any(|l| l.source == format!("${p}")))
        .cloned()
        .collect();
    (lists, missing)
}

/// `*` matches any run of characters: `WORK_*`, `*_TOKEN`, `*AZURE*`.
fn glob(pattern: &str, name: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    let [first, middle @ .., last] = parts.as_slice() else {
        return pattern == name; // no `*`: an exact name
    };
    if name.len() < first.len() + last.len() || !name.starts_with(first) || !name.ends_with(last) {
        return false;
    }
    let mut rest = &name[first.len()..name.len() - last.len()];
    for m in middle {
        match rest.find(m) {
            Some(i) => rest = &rest[i + m.len()..],
            None => return false,
        }
    }
    true
}

/// Loads, in order: the built-in packs, the `~/.config/redact/packs/` folder,
/// `~/.config/redact/config.toml` and everything it imports, then each `--file`.
/// Any file that will not load is an error naming it: a redactor that skips a
/// rule file would hide less than you think it does.
pub fn load(opts: &Options) -> Result<Loaded, String> {
    let mut l = Loader::default();
    if opts.builtin {
        for (name, text) in BUILTIN {
            let pack = compile(text, &format!("built-in {name}"))?;
            l.record(
                "builtin",
                name.to_string(),
                format!("{} rules", pack.rules.len()),
                None,
            );
            l.loaded.packs.push(pack);
        }
    }
    if opts.user {
        if let Some(dir) = config_home().map(|c| c.join("packs"))
            && dir.is_dir()
        {
            l.file(&dir, None)?;
        }
        match &opts.config {
            Some(c) => l.file(c, None)?,
            None => {
                if let Some(c) = config_home().map(|c| c.join("config.toml"))
                    && c.is_file()
                {
                    l.file(&c, None)?;
                }
            }
        }
    }
    for f in &opts.files {
        l.file(f, None)?;
    }
    Ok(l.loaded)
}

/// `~/.config/redact` on Linux and macOS (or `$XDG_CONFIG_HOME/redact`), and
/// `%APPDATA%\redact` on Windows: the same rule worktrunk and most CLIs use.
pub fn config_home() -> Option<PathBuf> {
    etcetera::choose_base_strategy()
        .ok()
        .map(|s| etcetera::BaseStrategy::config_dir(&s).join("redact"))
}

fn home() -> Option<PathBuf> {
    etcetera::home_dir().ok()
}

fn ext(p: &Path) -> &str {
    p.extension().and_then(|e| e.to_str()).unwrap_or("")
}

/// `~/x` (or `~\x`) is in your home folder; any other relative path is beside `importer`.
fn resolve(raw: &str, importer: &Path) -> PathBuf {
    if let Some(rest) = raw.strip_prefix("~/").or_else(|| raw.strip_prefix("~\\"))
        && let Some(home) = home()
    {
        return home.join(rest);
    }
    let p = PathBuf::from(raw);
    if p.is_absolute() {
        p
    } else {
        importer.parent().unwrap_or(Path::new(".")).join(p)
    }
}

/// Shows `/home/me/x` as `~/x`, so `config ls` reads the same on any machine.
pub fn tilde(p: &Path) -> String {
    match home().and_then(|h| p.strip_prefix(&h).ok().map(Path::to_path_buf)) {
        Some(rest) if !rest.as_os_str().is_empty() => {
            format!("~{}{}", std::path::MAIN_SEPARATOR, rest.display())
        }
        _ => p.display().to_string(),
    }
}

#[derive(Default)]
struct Loader {
    loaded: Loaded,
    /// Files already loaded: a file reached twice loads once.
    seen: HashSet<PathBuf>,
    /// The config files being imported right now, to catch a loop.
    stack: Vec<PathBuf>,
}

impl Loader {
    fn record(&mut self, kind: &'static str, path: String, detail: String, via: Option<&Path>) {
        self.loaded.sources.push(Source {
            kind,
            path,
            detail,
            via: via.map(tilde),
        });
    }

    fn file(&mut self, path: &Path, via: Option<&Path>) -> Result<(), String> {
        let shown = tilde(path);
        let named_by = via
            .map(|v| format!(" (imported by {})", tilde(v)))
            .unwrap_or_default();
        let canon = path
            .canonicalize()
            .map_err(|e| format!("{shown}{named_by}: {e}"))?;
        if self.stack.contains(&canon) {
            let chain: Vec<String> = self.stack.iter().map(|p| tilde(p)).chain([shown]).collect();
            return Err(format!("import loop: {}", chain.join(" -> ")));
        }
        if !self.seen.insert(canon.clone()) {
            return Ok(());
        }
        if canon.is_dir() {
            let mut children: Vec<PathBuf> = std::fs::read_dir(&canon)
                .map_err(|e| format!("{shown}: {e}"))?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| matches!(ext(p), "toml" | "txt"))
                .collect();
            children.sort();
            self.record("folder", shown, format!("{} files", children.len()), via);
            for c in &children {
                self.file(c, Some(&canon))?;
            }
            return Ok(());
        }
        let text =
            std::fs::read_to_string(&canon).map_err(|e| format!("{shown}{named_by}: {e}"))?;
        match ext(&canon) {
            "txt" => {
                let list = word_list(&canon, &text);
                self.record(
                    "words",
                    shown,
                    format!("{} entries as [{}-…]", list.words.len(), list.label),
                    via,
                );
                self.loaded.words.push(list);
            }
            // A pack has an `id`; a TOML file without one is a config file of imports.
            "toml" if text.lines().any(|l| l.trim_start().starts_with("id")) => {
                let pack = compile(&text, &shown)?;
                self.record(
                    "pack",
                    shown,
                    format!("{} ({} rules)", pack.id, pack.rules.len()),
                    via,
                );
                self.loaded.packs.push(pack);
            }
            "toml" => {
                let cfg: ConfigFile = toml::from_str(&text).map_err(|e| format!("{shown}: {e}"))?;
                self.record(
                    "config",
                    shown,
                    format!("{} imports", cfg.import.len()),
                    via,
                );
                self.stack.push(canon.clone());
                for raw in &cfg.import {
                    self.file(&resolve(raw, &canon), Some(&canon))?;
                }
                self.stack.pop();
                if !cfg.env.is_empty() {
                    let (lists, missing) = env_words(&cfg.env, std::env::vars());
                    let total: usize = lists.iter().map(|w| w.words.len()).sum();
                    let unset = if missing.is_empty() {
                        String::new()
                    } else {
                        format!("; not set: {}", missing.join(", "))
                    };
                    self.record(
                        "env",
                        cfg.env.join(", "),
                        format!("{} variables, {total} words{unset}", lists.len()),
                        Some(&canon),
                    );
                    self.loaded.words.extend(lists);
                }
            }
            other => {
                return Err(format!(
                    "{shown}{named_by}: unknown file type .{other}: use .toml for a pack or config, .txt for a word list"
                ));
            }
        }
        Ok(())
    }
}

/// A .txt list: one word or phrase per line, `#` starts a note. The file name is
/// the label, so `customers.txt` hides each line as `[CUSTOMERS-…]`.
fn word_list(path: &Path, text: &str) -> WordList {
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("word");
    WordList {
        label: label_of(stem),
        source: path.display().to_string(),
        words: text
            .lines()
            .map(str::trim)
            .filter(|l| l.chars().count() >= 3 && !l.starts_with('#'))
            .map(String::from)
            .collect(),
    }
}

pub fn label_of(name: &str) -> String {
    name.trim().to_uppercase().replace(['_', ' '], "-")
}

fn lower(v: Vec<String>) -> Vec<String> {
    v.into_iter().map(|k| k.to_lowercase()).collect()
}

fn compile(text: &str, source: &str) -> Result<Pack, String> {
    let f: PackFile = toml::from_str(text).map_err(|e| format!("{source}: {e}"))?;
    if f.schema_version != 1 {
        return Err(format!("{source}: schema_version must be 1"));
    }
    let mut rules = Vec::new();
    for r in f.rules {
        let re = Regex::new(&r.regex).map_err(|e| format!("{source}: rule {}: {e}", r.id))?;
        if r.secret_group >= re.captures_len() {
            return Err(format!(
                "{source}: rule {} hides group {}, but its regex has {} group(s)",
                r.id,
                r.secret_group,
                re.captures_len() - 1
            ));
        }
        let within = match &r.within {
            Some(w) => {
                Some(Regex::new(w).map_err(|e| format!("{source}: rule {} within: {e}", r.id))?)
            }
            None => None,
        };
        rules.push(Rule {
            label: label_of(r.label.as_deref().unwrap_or(&r.id)),
            id: r.id,
            description: r.description,
            re,
            group: r.secret_group,
            within,
            remember: r.remember,
            keywords: lower(r.keywords),
        });
    }
    Ok(Pack {
        id: f.id,
        description: f.description,
        source: source.to_string(),
        keywords: lower(f.keywords),
        allow: f.allow.into_iter().map(|a| a.to_lowercase()).collect(),
        rules,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(list: &[(&str, &str)]) -> impl Iterator<Item = (String, String)> {
        list.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn glob_star_anywhere() {
        for (p, n) in [
            ("WORK_*", "WORK_AZ_ORG"),
            ("*_TOKEN", "AZURE_TOKEN"),
            ("*AZURE*", "ORCA_AZURE_DEVOPS_TOKEN"),
            ("A*B*C", "AxxBxxC"),
            ("*", "ANY"),
        ] {
            assert!(glob(p, n), "{p} should match {n}");
        }
        for (p, n) in [
            ("*_TOKEN", "TOKEN"),
            ("*_TOKEN", "AZURE_TOKENS"),
            ("WORK_*", "WORKSPACE"),
            ("A*B*C", "AxxCxxB"),
            ("PR_HOST", "PR_HOSTS"),
        ] {
            assert!(!glob(p, n), "{p} should not match {n}");
        }
    }

    #[test]
    fn env_names_and_prefixes_pick_variables() {
        let set = [
            ("WORK_AZ_ORG", "fabrikam-dev"),
            ("WORK_CUSTOMERS", "# note\nNorthwind Traders\nContoso"),
            ("PATH", "/usr/bin"),
            ("WORKSPACE", "x"),
        ];
        let (lists, missing) = env_words(&["WORK_*".into(), "EMPLOYER".into()], vars(&set));
        let got: Vec<(&str, Vec<&str>)> = lists
            .iter()
            .map(|w| {
                (
                    w.label.as_str(),
                    w.words.iter().map(String::as_str).collect(),
                )
            })
            .collect();
        assert_eq!(
            got,
            [
                ("WORK-AZ-ORG", vec!["fabrikam-dev"]),
                ("WORK-CUSTOMERS", vec!["Northwind Traders", "Contoso"])
            ]
        );
        assert_eq!(
            missing,
            ["EMPLOYER"],
            "an exact name that is not set is reported"
        );
    }
}
