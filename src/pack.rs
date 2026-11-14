//! Loading packs (.toml rule files) and word lists (.txt, one word per line).

use regex::Regex;
use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Packs compiled into the binary, so `redact` works with no config at all.
const BUILTIN: &[(&str, &str)] = &[
    // Specific packs first: when two rules hide exactly the same text, the first label wins.
    ("azure", include_str!("../packs/azure.toml")),
    ("identity", include_str!("../packs/identity.toml")),
    ("kubernetes", include_str!("../packs/kubernetes.toml")),
    ("docker", include_str!("../packs/docker.toml")),
    ("npm", include_str!("../packs/npm.toml")),
    ("http", include_str!("../packs/http.toml")),
    ("gcp", include_str!("../packs/gcp.toml")),
    ("credentials", include_str!("../packs/credentials.toml")),
    ("pii", include_str!("../packs/pii.toml")),
];

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
    /// `false`: the pack loads switched off, until `[packs] enable` names it.
    #[serde(default = "on")]
    default: bool,
}

fn on() -> bool {
    true
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
    except: Option<String>,
    except_match: Option<String>,
    /// A checksum the value must pass: `"luhn"` (card numbers) or `"iban"`.
    check: Option<String>,
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
    /// A found value that matches this is left alone: a reference such as
    /// `$AZURE_TOKEN`, not a secret. Rust's regex has no lookahead, so this is
    /// how a rule says "but not these".
    pub except: Option<Regex>,
    /// A whole match that matches this is left alone: `except` sees only the
    /// value, this sees the name beside it too (`nextPageToken: …`).
    pub except_match: Option<Regex>,
    /// A checksum the found value must pass, or it is left alone.
    pub check: Option<Check>,
    pub remember: Remember,
    pub keywords: Vec<String>,
}

pub struct Pack {
    pub id: String,
    pub description: String,
    pub source: String,
    pub keywords: Vec<String>,
    /// The allow list, lower-cased for matching.
    pub allow: HashSet<String>,
    /// The allow list as the pack wrote it, for the docs.
    pub allow_as_written: Vec<String>,
    pub rules: Vec<Rule>,
    /// Off unless a config's `[packs] enable` names it (`default = false`).
    pub on_by_default: bool,
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
    /// Values never hidden, lower-cased: the configs' `allow` lists.
    pub allow: HashSet<String>,
    /// Packs switched off, by `[packs] disable` or their own `default = false`:
    /// listed by `redact packs`, never used to scan.
    pub off: Vec<Pack>,
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
    /// `--env-file`: dotenv files whose values to hide. A missing one is an error.
    pub env_files: Vec<PathBuf>,
    /// `--command`: the command whose output this is, for `[[override]] command`.
    pub command: Option<String>,
    /// The folder and machine `[[override]] dir` and `host` match against. `None`
    /// means the real current folder and this machine's name.
    pub cwd: Option<PathBuf>,
    pub host: Option<String>,
}

/// A config file lists more files to load (packs, word lists, folders of either,
/// other config files; paths are relative to the file that names them), and the
/// environment variables whose values to hide.
///
/// `env` is how redact works with fnox, mise or anything else that sets
/// variables, without reading their files: `env = ["WORK_*"]` hides whatever
/// the `WORK_` variables hold when redact runs, e.g. under `fnox exec -- redact`.
///
/// `env_files` hides every value in dotenv files, like `dotenvx run` does. Unlike
/// imports, a relative path is relative to where redact runs, so `".env"` means
/// the current project's; one that is not there is listed as missing, not an error.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    #[serde(default)]
    import: Vec<String>,
    #[serde(default)]
    env: Vec<String>,
    #[serde(default)]
    env_files: Vec<String>,
    /// Hide who you are: your git name and email, and your GitHub login.
    #[serde(default)]
    me: bool,
    /// Values never hidden, in any case. `$NAME` reads an environment variable.
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    packs: PackSelect,
    /// Settings that apply only on a machine, in a folder, or for a command.
    #[serde(default, rename = "override")]
    overrides: Vec<Override>,
}

/// `[packs]`: switch built-in or loaded packs on (`enable`) or off (`disable`) by id.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct PackSelect {
    #[serde(default)]
    enable: Vec<String>,
    #[serde(default)]
    disable: Vec<String>,
}

/// `[[override]]`: settings that apply when every condition given matches.
/// `host` is this machine's name, `dir` the folder redact runs in (`~/` allowed),
/// `command` what `--command` named. Each is a glob: `*` matches anything.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Override {
    host: Option<String>,
    dir: Option<String>,
    command: Option<String>,
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    env: Vec<String>,
    #[serde(default)]
    env_files: Vec<String>,
    #[serde(default)]
    packs: PackSelect,
}

/// GitHub logins in gh's `hosts.yml`: each host's `user:`, and the names under
/// its `users:` map (gh keeps one entry per account you have signed in with).
fn gh_logins(hosts_yml: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_users = false;
    for line in hosts_yml.lines() {
        let indent = line.len() - line.trim_start().len();
        let t = line.trim();
        if let Some(v) = t.strip_prefix("user:") {
            in_users = false;
            out.push(v.trim().to_string());
        } else if t == "users:" {
            in_users = true;
        } else if in_users && indent >= 8 && t.ends_with(':') && !t.contains(' ') {
            out.push(t.trim_end_matches(':').to_string());
        } else if indent <= 4 {
            in_users = false;
        }
    }
    out.retain(|l| !l.is_empty());
    out.sort();
    out.dedup();
    out
}

/// gh's config folder: `$GH_CONFIG_DIR`, else `%AppData%\GitHub CLI` on Windows,
/// else `$XDG_CONFIG_HOME/gh` or `~/.config/gh`.
fn gh_config_dir() -> Option<PathBuf> {
    if let Some(d) = std::env::var_os("GH_CONFIG_DIR") {
        return Some(PathBuf::from(d));
    }
    if cfg!(windows) {
        return std::env::var_os("APPDATA").map(|a| PathBuf::from(a).join("GitHub CLI"));
    }
    etcetera::choose_base_strategy()
        .ok()
        .map(|s| etcetera::BaseStrategy::config_dir(&s).join("gh"))
}

/// `git config --get <key>`, here and globally (an `includeIf` can give a repo
/// its own email). git not installed, or the key not set, gives nothing.
fn git_values(key: &str) -> Vec<String> {
    let run = |args: &[&str]| {
        std::process::Command::new("git")
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|s| !s.is_empty())
    };
    let mut v: Vec<String> = [
        run(&["config", "--get", key]),
        run(&["config", "--global", "--get", key]),
    ]
    .into_iter()
    .flatten()
    .collect();
    v.dedup();
    v
}

/// Values in a dotenv file that are settings, not secrets: hiding `true` or
/// `3000` or `localhost` everywhere would wreck ordinary text.
fn is_setting(v: &str) -> bool {
    const COMMON: &[&str] = &[
        "true",
        "false",
        "yes",
        "no",
        "on",
        "off",
        "null",
        "none",
        "localhost",
        "development",
        "production",
        "staging",
        "test",
        "debug",
        "info",
        "warn",
        "warning",
        "error",
        "trace",
    ];
    v.chars().count() < 4
        || v.chars().all(|c| c.is_ascii_digit() || c == '.')
        || COMMON.contains(&v.to_ascii_lowercase().as_str())
}

/// The byte offset of the first `"` in `s` that a backslash does not escape.
fn closing_quote(s: &str) -> Option<usize> {
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '"' => return Some(i),
            _ => {}
        }
    }
    None
}

/// A double-quoted dotenv value's escapes: `\n`, `\"` and `\\`. Any other
/// backslash is kept as it is.
fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// The values of a dotenv file: `KEY=value`, `export KEY=value`, single or double
/// quotes (a double-quoted value may span lines), `#` comments. Skips empty
/// values, settings (see `is_setting`), `encrypted:` values (ciphertext hides
/// nothing) and `DOTENV_PUBLIC_KEY*`, as dotenvx does. The key is the label.
fn dotenv_words(text: &str, source: &str) -> Vec<WordList> {
    let mut out = Vec::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let line = line.trim_start();
        let line = line.strip_prefix("export ").unwrap_or(line);
        if line.starts_with('#') {
            continue;
        }
        let Some((key, raw)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let raw = raw.trim();
        let value = if let Some(rest) = raw.strip_prefix('"') {
            // Up to the closing quote that is not escaped, across lines if need be.
            // Whatever follows it (a `# comment`) is not part of the value.
            let mut v = String::new();
            let mut chunk = rest.to_string();
            loop {
                if let Some(end) = closing_quote(&chunk) {
                    v.push_str(&chunk[..end]);
                    break;
                }
                v.push_str(&chunk);
                match lines.next() {
                    Some(next) => {
                        v.push('\n');
                        chunk = next.to_string();
                    }
                    None => break,
                }
            }
            unescape(&v)
        } else if let Some((q, rest)) = raw
            .strip_prefix('\'')
            .map(|r| ('\'', r))
            .or_else(|| raw.strip_prefix('`').map(|r| ('`', r)))
        {
            // Single quotes and backticks: literal up to the closing one, across
            // lines if need be; no escapes.
            let mut v = String::new();
            let mut chunk = rest.to_string();
            loop {
                if let Some((inside, _)) = chunk.split_once(q) {
                    v.push_str(inside);
                    break;
                }
                v.push_str(&chunk);
                match lines.next() {
                    Some(next) => {
                        v.push('\n');
                        chunk = next.to_string();
                    }
                    None => break,
                }
            }
            v
        } else {
            // Unquoted: up to a `#` that follows any whitespace (a space or a tab).
            let cut = raw
                .char_indices()
                .find(|&(i, c)| c == '#' && i > 0 && raw[..i].ends_with(char::is_whitespace))
                .map_or(raw.len(), |(i, _)| i);
            raw[..cut].trim().to_string()
        };
        if key.is_empty() || key.starts_with("DOTENV_PUBLIC_KEY") || value.starts_with("encrypted:")
        {
            continue;
        }
        let words: Vec<String> = value
            .lines()
            .map(str::trim)
            .filter(|w| !w.is_empty() && !is_setting(w))
            .map(String::from)
            .collect();
        if !words.is_empty() {
            out.push(WordList {
                label: label_of(key),
                source: source.to_string(),
                words,
            });
        }
    }
    out
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
                // Settings (`true`, `3000`, `development`) would hide ordinary text.
                .filter(|l| l.chars().count() >= 3 && !l.starts_with('#') && !is_setting(l))
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
    let mut l = Loader {
        host: opts.host.clone().unwrap_or_else(hostname),
        cwd: opts
            .cwd
            .clone()
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_default(),
        command: opts.command.clone(),
        ..Loader::default()
    };
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
        // `-c` replaces the whole user layer, as fnox's `-c` does: that file
        // and what it imports, not the default packs folder beside it.
        match &opts.config {
            Some(c) => l.file(c, None)?,
            None => {
                if let Some(dir) = config_home().map(|c| c.join("packs"))
                    && dir.is_dir()
                {
                    l.file(&dir, None)?;
                }
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
    for f in &opts.env_files {
        l.env_file(f, None, true)?;
    }
    select_packs(&mut l)?;
    Ok(l.loaded)
}

/// Applies `[packs]`: a pack runs when it is on by default and not disabled, or
/// when enabled. `disable` also takes one rule as `pack:rule`, as `--explain`
/// prints it. A name that matches nothing is an error, so a typo is caught.
fn select_packs(l: &mut Loader) -> Result<(), String> {
    let ids: HashSet<&str> = l.loaded.packs.iter().map(|p| p.id.as_str()).collect();
    let rule_ids: HashSet<String> = l
        .loaded
        .packs
        .iter()
        .flat_map(|p| p.rules.iter().map(move |r| format!("{}:{}", p.id, r.id)))
        .collect();
    let mut unknown: Vec<&String> = l
        .enable
        .iter()
        .filter(|n| !ids.contains(n.as_str()))
        .chain(
            l.disable
                .iter()
                .filter(|n| !ids.contains(n.as_str()) && !rule_ids.contains(n.as_str())),
        )
        .collect();
    if !unknown.is_empty() {
        unknown.sort();
        let mut known: Vec<&str> = ids.into_iter().collect();
        known.sort();
        return Err(format!(
            "[packs] names no such pack or pack:rule: {} (packs: {}; `redact packs` lists their rules)",
            unknown
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            known.join(", ")
        ));
    }
    let (enable, disable) = (&l.enable, &l.disable);
    for p in &mut l.loaded.packs {
        p.rules
            .retain(|r| !disable.contains(&format!("{}:{}", p.id, r.id)));
    }
    let off: Vec<String> = l
        .loaded
        .packs
        .iter()
        .filter(|p| disable.contains(&p.id) || (!p.on_by_default && !enable.contains(&p.id)))
        .map(|p| p.id.clone())
        .collect();
    let (on, off_packs) = std::mem::take(&mut l.loaded.packs)
        .into_iter()
        .partition(|p| !off.contains(&p.id));
    l.loaded.packs = on;
    l.loaded.off = off_packs;
    for s in &mut l.loaded.sources {
        let id = if s.kind == "builtin" {
            s.path.as_str()
        } else {
            s.detail.split(' ').next().unwrap_or("")
        };
        if matches!(s.kind, "builtin" | "pack") && off.iter().any(|o| o == id) {
            s.detail = format!("{}, off", s.detail);
        }
    }
    Ok(())
}

/// This machine's name, for `[[override]] host`: `COMPUTERNAME` on Windows,
/// `HOSTNAME`, `/etc/hostname`, else the `hostname` command (macOS).
fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        })
        .map(|h| h.trim().to_string())
        .unwrap_or_default()
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

/// A file's extension in lower case, so `Clients.TXT` is a word list too.
fn ext(p: &Path) -> String {
    p.extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
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
    /// What `[[override]]` sections match against.
    host: String,
    cwd: PathBuf,
    command: Option<String>,
    /// `[packs]` from every config and matching override.
    enable: HashSet<String>,
    disable: HashSet<String>,
}

impl Loader {
    /// `me = true`: your git user.name and user.email, and your GitHub logins
    /// from gh's hosts.yml, hidden everywhere as [ME-NAME-…], [ME-EMAIL-…] and
    /// [ME-GITHUB-…]. What is not set is skipped; `config ls` lists what was found.
    fn me(&mut self, via: &Path) {
        let gh = gh_config_dir()
            .and_then(|d| std::fs::read_to_string(d.join("hosts.yml")).ok())
            .map(|t| gh_logins(&t))
            .unwrap_or_default();
        let mut found = Vec::new();
        for (label, words) in [
            ("ME-NAME", git_values("user.name")),
            ("ME-EMAIL", git_values("user.email")),
            ("ME-GITHUB", gh),
        ] {
            let words: Vec<String> = words
                .into_iter()
                .filter(|w| w.chars().count() >= 3)
                .collect();
            if !words.is_empty() {
                found.push(format!(
                    "{} {}",
                    words.len(),
                    label.trim_start_matches("ME-").to_lowercase()
                ));
                self.loaded.words.push(WordList {
                    label: label.into(),
                    source: "me".into(),
                    words,
                });
            }
        }
        let detail = if found.is_empty() {
            "nothing found".into()
        } else {
            found.join(", ")
        };
        self.record("me", "git config, gh hosts.yml".into(), detail, Some(via));
    }

    /// The settings a config and its matching overrides share: env, env_files,
    /// allow and [packs].
    fn apply(
        &mut self,
        env: &[String],
        env_files: &[String],
        allow: &[String],
        packs: &PackSelect,
        via: &Path,
    ) -> Result<(), String> {
        if !env.is_empty() {
            let (lists, missing) = env_words(env, std::env::vars());
            let total: usize = lists.iter().map(|w| w.words.len()).sum();
            let unset = if missing.is_empty() {
                String::new()
            } else {
                format!("; not set: {}", missing.join(", "))
            };
            self.record(
                "env",
                env.join(", "),
                format!("{} variables, {total} words{unset}", lists.len()),
                Some(via),
            );
            self.loaded.words.extend(lists);
        }
        for raw in env_files {
            let path = match raw.strip_prefix("~/").zip(home()) {
                Some((rest, h)) => h.join(rest),
                None => PathBuf::from(raw), // relative: to where redact runs
            };
            self.env_file(&path, Some(via), false)?;
        }
        if !allow.is_empty() {
            // `$NAME` reads an environment variable, so the value need not sit in the file.
            let mut unset = Vec::new();
            let mut n = 0;
            for a in allow {
                match a.strip_prefix('$') {
                    Some(name) => match std::env::var(name) {
                        Ok(v) if !v.trim().is_empty() => {
                            self.loaded.allow.insert(v.trim().to_lowercase());
                            n += 1;
                        }
                        _ => unset.push(a.clone()),
                    },
                    None => {
                        self.loaded.allow.insert(a.to_lowercase());
                        n += 1;
                    }
                }
            }
            let unset = if unset.is_empty() {
                String::new()
            } else {
                format!("; not set: {}", unset.join(", "))
            };
            self.record(
                "allow",
                format!("{} entries", allow.len()),
                format!("{n} values{unset}"),
                Some(via),
            );
        }
        self.enable.extend(packs.enable.iter().cloned());
        self.disable.extend(packs.disable.iter().cloned());
        Ok(())
    }

    /// Why an override applies (`host=…, dir=…`), or `None` when one of its
    /// conditions does not match. An override with no condition always applies.
    fn matches(&self, o: &Override) -> Option<String> {
        let mut why = Vec::new();
        if let Some(h) = &o.host {
            if !glob(&h.to_lowercase(), &self.host.to_lowercase()) {
                return None;
            }
            why.push(format!("host={h}"));
        }
        if let Some(d) = &o.dir {
            let d_expanded = match d.strip_prefix("~/").zip(home()) {
                Some((rest, h)) => h.join(rest).display().to_string(),
                None => d.clone(),
            };
            // Compare with `/` on every system, so one config works on Windows too.
            let (d_expanded, cwd) = (
                d_expanded.replace('\\', "/"),
                self.cwd.display().to_string().replace('\\', "/"),
            );
            // `dir = "~/x"` matches ~/x and everything below it.
            let below = format!("{}/*", d_expanded.trim_end_matches(['/', '*']));
            if !glob(&d_expanded, &cwd) && !glob(&below, &cwd) {
                return None;
            }
            why.push(format!("dir={d}"));
        }
        if let Some(c) = &o.command {
            if !self.command.as_deref().is_some_and(|cmd| glob(c, cmd)) {
                return None;
            }
            why.push(format!("command={c}"));
        }
        Some(if why.is_empty() {
            "always".into()
        } else {
            why.join(", ")
        })
    }

    /// A dotenv file's values. `required` (from `--env-file`) makes a missing file
    /// an error; from a config's `env_files` it is listed as not found instead,
    /// since a project may simply not have one.
    fn env_file(&mut self, path: &Path, via: Option<&Path>, required: bool) -> Result<(), String> {
        let shown = tilde(path);
        let text = match read_text(path) {
            Ok(t) => t,
            Err(e) if !required && e.kind() == std::io::ErrorKind::NotFound => {
                self.record("dotenv", shown, "not found here".into(), via);
                return Ok(());
            }
            Err(e) => return Err(format!("{shown}: {e}")),
        };
        let lists = dotenv_words(&text, &shown);
        let total: usize = lists.iter().map(|w| w.words.len()).sum();
        self.record(
            "dotenv",
            shown,
            format!("{} keys, {total} values", lists.len()),
            via,
        );
        self.loaded.words.extend(lists);
        Ok(())
    }

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
            // Subfolders load too. Any other file is listed as skipped, so a
            // `clients.list` that redact cannot read does not vanish silently.
            // Hidden files (`.DS_Store`) are left out of that list.
            let mut entries: Vec<PathBuf> = std::fs::read_dir(&canon)
                .map_err(|e| format!("{shown}: {e}"))?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| {
                    !p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with('.'))
                })
                .collect();
            entries.sort();
            let (load, skip): (Vec<PathBuf>, Vec<PathBuf>) = entries
                .into_iter()
                .partition(|p| p.is_dir() || matches!(ext(p).as_str(), "toml" | "txt"));
            let mut detail = format!("{} files and folders", load.len());
            if !skip.is_empty() {
                let names: Vec<String> = skip
                    .iter()
                    .filter_map(|p| p.file_name().and_then(|n| n.to_str()).map(String::from))
                    .collect();
                detail.push_str(&format!(
                    "; skipped, not .toml or .txt: {}",
                    names.join(", ")
                ));
            }
            self.record("folder", shown, detail, via);
            for c in &load {
                self.file(c, Some(&canon))?;
            }
            return Ok(());
        }
        let text = read_text(&canon).map_err(|e| format!("{shown}{named_by}: {e}"))?;
        match ext(&canon).as_str() {
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
                self.apply(&cfg.env, &cfg.env_files, &cfg.allow, &cfg.packs, &canon)?;
                if cfg.me {
                    self.me(&canon);
                }
                for o in &cfg.overrides {
                    if let Some(why) = self.matches(o) {
                        self.record("override", why, "applies".into(), Some(&canon));
                        self.apply(&o.env, &o.env_files, &o.allow, &o.packs, &canon)?;
                    }
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
            // A note after a word: `Contoso # main customer`. `C#` stays whole.
            .map(|l| {
                l.split([' ', '\t'])
                    .take_while(|w| !w.starts_with('#'))
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .map(|l| l.trim().to_string())
            .filter(|l| l.chars().count() >= 3)
            .collect(),
    }
}

/// A text file, without the byte-order mark Windows editors put at the start
/// (it would otherwise stick to the first word or key).
fn read_text(path: &Path) -> std::io::Result<String> {
    let text = std::fs::read_to_string(path)?;
    Ok(match text.strip_prefix('\u{feff}') {
        Some(rest) => rest.to_string(),
        None => text,
    })
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
        let except = match &r.except {
            Some(x) => {
                Some(Regex::new(x).map_err(|e| format!("{source}: rule {} except: {e}", r.id))?)
            }
            None => None,
        };
        let except_match = match &r.except_match {
            Some(x) => Some(
                Regex::new(x).map_err(|e| format!("{source}: rule {} exceptMatch: {e}", r.id))?,
            ),
            None => None,
        };
        let check = match r.check.as_deref() {
            None => None,
            Some("luhn") => Some(Check::Luhn),
            Some("iban") => Some(Check::Iban),
            Some(other) => {
                return Err(format!(
                    "{source}: rule {} check \"{other}\": use \"luhn\" or \"iban\"",
                    r.id
                ));
            }
        };
        rules.push(Rule {
            label: label_of(r.label.as_deref().unwrap_or(&r.id)),
            id: r.id,
            description: r.description,
            re,
            group: r.secret_group,
            within,
            except,
            except_match,
            check,
            remember: r.remember,
            keywords: lower(r.keywords),
        });
    }
    Ok(Pack {
        id: f.id,
        description: f.description,
        source: source.to_string(),
        keywords: lower(f.keywords),
        allow: f.allow.iter().map(|a| a.to_lowercase()).collect(),
        allow_as_written: f.allow,
        rules,
        on_by_default: f.default,
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
    fn dotenv_backticks_multiline_single_quotes_and_tab_comments() {
        // Third review: three more dotenv forms.
        let text =
            "A=`alpha-tick-1`\nB='bravo\nline-two'\nC=charlie-val-3\t# note\nD=delta-val-4\n";
        let got: Vec<(String, Vec<String>)> = dotenv_words(text, ".env")
            .into_iter()
            .map(|w| (w.label, w.words))
            .collect();
        assert_eq!(
            got,
            [
                ("A".to_string(), vec!["alpha-tick-1".to_string()]),
                ("B".into(), vec!["bravo".into(), "line-two".into()]),
                ("C".into(), vec!["charlie-val-3".into()]),
                ("D".into(), vec!["delta-val-4".into()]),
            ]
        );
    }

    #[test]
    fn env_values_that_are_settings_are_not_hidden() {
        let set = [("WORK_DEBUG", "true"), ("WORK_ORG", "fabrikamq-dev")];
        let (lists, _) = env_words(&["WORK_*".into()], vars(&set));
        let words: Vec<&str> = lists
            .iter()
            .flat_map(|w| w.words.iter().map(String::as_str))
            .collect();
        assert_eq!(words, ["fabrikamq-dev"]);
    }

    #[test]
    fn dotenv_quoted_values_with_comments() {
        // Review 2026-11-14: a comment after a quoted value swallowed the next line.
        let text = "ALPHA=\"alpha-value-1\" # a note\nBETA=bravo-value-2\nGAMMA='gamma-value-3' # another\nDELTA=\"multi\nline-value\" # end\nECHO=\"has \\\"quote\\\" inside\"\n";
        let got: Vec<(String, Vec<String>)> = dotenv_words(text, ".env")
            .into_iter()
            .map(|w| (w.label, w.words))
            .collect();
        assert_eq!(
            got,
            [
                ("ALPHA".to_string(), vec!["alpha-value-1".to_string()]),
                ("BETA".into(), vec!["bravo-value-2".into()]),
                ("GAMMA".into(), vec!["gamma-value-3".into()]),
                ("DELTA".into(), vec!["multi".into(), "line-value".into()]),
                ("ECHO".into(), vec!["has \"quote\" inside".into()]),
            ]
        );
    }

    #[test]
    fn dotenv_values_but_not_settings() {
        let text = r#"
# a comment
export AZURE_ORGANISATION=fabrikam-dev
PROJECT_NAME="Bluefin Portal"
API_TOKEN='s3cr3t-value-123'
CERT="-----BEGIN-----
abcdefgh
-----END-----"
INLINE=bluefin-api # the api app
PORT=3000
DEBUG=true
NODE_ENV=development
EMPTY=
DOTENV_PUBLIC_KEY=03abc0123456789
SECRET=encrypted:BDqDBibm4wsYqMpCjTQ6BsDHmMadg9K3dhERmPh8
"#;
        let lists = dotenv_words(text, ".env");
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
                ("AZURE-ORGANISATION", vec!["fabrikam-dev"]),
                ("PROJECT-NAME", vec!["Bluefin Portal"]),
                ("API-TOKEN", vec!["s3cr3t-value-123"]),
                ("CERT", vec!["-----BEGIN-----", "abcdefgh", "-----END-----"]),
                ("INLINE", vec!["bluefin-api"]),
            ]
        );
    }

    #[test]
    fn gh_logins_from_hosts_yml() {
        let yml = "github.com:\n    git_protocol: ssh\n    users:\n        quillfeatherq:\n            oauth_token: x\n        workaccountq:\n            oauth_token: y\n    user: quillfeatherq\n    oauth_token: x\nghe.example.com:\n    user: jq-enterprise\n";
        assert_eq!(
            gh_logins(yml),
            ["jq-enterprise", "quillfeatherq", "workaccountq"]
        );
        assert!(gh_logins("").is_empty());
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

/// A checksum a found value must pass. Without one, any long run of digits
/// would read as a card number.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Check {
    /// Card numbers: 13 to 19 digits (spaces and dashes ignored) passing Luhn.
    Luhn,
    /// IBANs: 15 to 34 characters (spaces ignored) passing ISO 7064 mod 97.
    Iban,
}

impl Check {
    pub fn passes(self, value: &str) -> bool {
        match self {
            Check::Luhn => {
                let digits: Vec<u32> = value.chars().filter_map(|c| c.to_digit(10)).collect();
                if !(13..=19).contains(&digits.len())
                    || value
                        .chars()
                        .any(|c| !c.is_ascii_digit() && c != ' ' && c != '-')
                {
                    return false;
                }
                let sum: u32 = digits
                    .iter()
                    .rev()
                    .enumerate()
                    .map(|(i, &d)| {
                        if i % 2 == 1 {
                            (d * 2) % 9 + if d == 9 { 9 } else { 0 }
                        } else {
                            d
                        }
                    })
                    .sum();
                sum.is_multiple_of(10)
            }
            Check::Iban => {
                let s: String = value.chars().filter(|c| !c.is_whitespace()).collect();
                if !(15..=34).contains(&s.len()) || !s.chars().all(|c| c.is_ascii_alphanumeric()) {
                    return false;
                }
                let (head, tail) = s.split_at(4);
                let mut rem: u32 = 0;
                for c in tail.chars().chain(head.chars()) {
                    let n = c.to_digit(36).expect("checked alphanumeric");
                    for d in n.to_string().chars() {
                        rem = (rem * 10 + d.to_digit(10).expect("a digit")) % 97;
                    }
                }
                rem == 1
            }
        }
    }
}
