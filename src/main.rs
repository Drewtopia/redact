//! redact: keep secrets, names, and sensitive information out of what AI sees.
//!
//! Exit codes: 0 done, 2 bad usage, 3 a pack would not load or the scan failed.

mod pack;
mod scan;

use clap::{CommandFactory, Parser, Subcommand};
use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

/// Keep secrets, names, and sensitive information out of what AI sees.
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    /// Also load this pack (.toml) or word list (.txt). Repeatable.
    #[arg(long = "file", short = 'f', global = true, value_name = "PATH")]
    files: Vec<PathBuf>,

    /// Load only --file: skip the built-in packs and everything in ~/.config/redact.
    #[arg(long, global = true)]
    only_files: bool,

    /// Use this config file instead of ~/.config/redact/config.toml.
    #[arg(
        long,
        short = 'c',
        global = true,
        env = "REDACT_CONFIG",
        value_name = "PATH"
    )]
    config: Option<PathBuf>,

    /// Also hide every value in this dotenv file (`.env`). Repeatable.
    #[arg(long = "env-file", global = true, value_name = "PATH")]
    env_files: Vec<PathBuf>,

    /// The command whose output this is, for `[[override]] command = "..."`.
    #[arg(
        long = "command",
        global = true,
        env = "REDACT_COMMAND",
        value_name = "COMMAND"
    )]
    for_command: Option<String>,

    /// With no command, piped input is scanned: `az account show | redact`.
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Read text on stdin and write it back with sensitive parts as placeholders.
    Scan {
        /// Print the parts to hide as JSON byte spans instead of the masked text.
        #[arg(long)]
        json: bool,
        /// Also say on stderr which rule hid each part (never the value).
        #[arg(long)]
        explain: bool,
    },
    /// List the packs and word lists that load, and where each comes from.
    Packs,
    /// Show the config files and what they load.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Print a shell completion script, e.g. `redact completions zsh`.
    Completions { shell: clap_complete::Shell },
    /// Print shell setup: completions plus `redacted <cmd>`, which runs a
    /// command and masks its output, stderr included, keeping its exit status.
    ///
    /// Add one line to your shell's startup file:
    ///
    ///   bash  ~/.bashrc                        eval "$(redact init bash)"
    ///   zsh   ~/.zshrc                         eval "$(redact init zsh)"
    ///   fish  ~/.config/fish/config.fish       redact init fish | source
    ///   pwsh  $PROFILE                         Invoke-Expression (& redact init powershell | Out-String)
    ///   elvish ~/.config/elvish/rc.elv         eval (redact init elvish | slurp)
    #[command(verbatim_doc_comment)]
    Init { shell: clap_complete::Shell },
}

/// The `redacted` helper `redact init` prints for each shell. It merges
/// stderr into stdout, passes the command line as `--command`, and keeps the
/// command's exit status.
fn init_helper(shell: clap_complete::Shell) -> &'static str {
    use clap_complete::Shell;
    match shell {
        Shell::Bash => {
            r#"redacted() { "$@" 2>&1 | redact scan --command "$*"; return "${PIPESTATUS[0]}"; }
"#
        }
        Shell::Zsh => {
            r#"redacted() { "$@" 2>&1 | redact scan --command "$*"; return "${pipestatus[1]}"; }
"#
        }
        Shell::Fish => {
            r#"function redacted
    $argv 2>&1 | redact scan --command "$argv"
    return $pipestatus[1]
end
"#
        }
        // shortcut: buffers the output to keep the exit code; stream it if long runs need live output.
        Shell::PowerShell => {
            r#"function redacted {
    $c = $args -join ' '
    $rest = @($args | Select-Object -Skip 1)
    $out = & $args[0] @rest 2>&1
    $code = $LASTEXITCODE
    $out | ForEach-Object { "$_" } | redact scan --command $c
    $global:LASTEXITCODE = $code
}
"#
        }
        Shell::Elvish => {
            r#"use str
fn redacted {|@a| var rest = $a[1..]; (external $a[0]) $@rest 2>&1 | redact scan --command (str:join ' ' $a) }
"#
        }
        _ => "",
    }
}

#[derive(Subcommand)]
enum ConfigAction {
    /// List every file that loads, in load order, and what imported it.
    Ls,
    /// Write a starter config: `minimal` by default.
    Init {
        /// Which starter to write.
        #[arg(long, value_enum, default_value_t = Preset::Minimal)]
        preset: Preset,
        /// Replace an existing config file.
        #[arg(long)]
        force: bool,
        /// Print the starter config instead of writing it.
        #[arg(long)]
        print: bool,
    },
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum Preset {
    /// Hides you, secret-named environment variables and .env files.
    Minimal,
    /// Every setting that needs none of your own names, switched on, pii included.
    Full,
    /// Every setting shown and switched off, as a reference.
    Commented,
}

/// The starter configs `redact config init` writes. Tests load each, so none
/// can drift into an example that does not parse.
const STARTER_CONFIG: &str = include_str!("../config.example.toml");
const MINIMAL_CONFIG: &str = include_str!("../config.minimal.toml");
const FULL_CONFIG: &str = include_str!("../config.full.toml");

/// `redact config init`: writes the starter config unless one is there already.
fn config_init(path: Option<PathBuf>, preset: Preset, force: bool, print: bool) -> ExitCode {
    let starter = match preset {
        Preset::Minimal => MINIMAL_CONFIG,
        Preset::Full => FULL_CONFIG,
        Preset::Commented => STARTER_CONFIG,
    };
    if print {
        print!("{starter}");
        return ExitCode::SUCCESS;
    }
    let Some(path) = path.or_else(|| pack::config_home().map(|h| h.join("config.toml"))) else {
        return fail("cannot find your config folder; pass -c <path>");
    };
    if path.exists() && !force {
        eprintln!(
            "redact: {} already exists; --force replaces it, --print shows the starter",
            pack::tilde(&path)
        );
        return ExitCode::from(2);
    }
    if let Some(dir) = path.parent()
        && let Err(e) = std::fs::create_dir_all(dir)
    {
        return fail(&format!("{}: {e}", dir.display()));
    }
    match std::fs::write(&path, starter) {
        Ok(()) => {
            println!("wrote {}", pack::tilde(&path));
            ExitCode::SUCCESS
        }
        Err(e) => fail(&format!("{}: {e}", path.display())),
    }
}

fn main() -> ExitCode {
    let mut cli = Cli::parse();
    let command = match cli.command.take() {
        Some(c) => c,
        None if !std::io::stdin().is_terminal() => Command::Scan {
            json: false,
            explain: false,
        },
        None => {
            Cli::command().print_help().ok();
            return ExitCode::from(2);
        }
    };
    if let Command::Completions { shell } | Command::Init { shell } = &command {
        clap_complete::generate(
            *shell,
            &mut Cli::command(),
            "redact",
            &mut std::io::stdout(),
        );
        // After the completions: PowerShell's open with `using namespace`,
        // which must come before any other statement.
        if let Command::Init { shell } = &command {
            print!("{}", init_helper(*shell));
        }
        return ExitCode::SUCCESS;
    }
    // Before loading, so a broken config can still be replaced.
    if let Command::Config {
        action:
            ConfigAction::Init {
                preset,
                force,
                print,
            },
    } = &command
    {
        return config_init(cli.config.clone(), *preset, *force, *print);
    }
    let opts = pack::Options {
        files: cli.files,
        builtin: !cli.only_files,
        user: !cli.only_files,
        config: cli.config,
        env_files: cli.env_files,
        command: cli.for_command,
        cwd: None,
        host: None,
    };
    let loaded = match pack::load(&opts) {
        Ok(l) => l,
        Err(e) => return fail(&e),
    };
    match command {
        Command::Packs => emit(print_packs(&mut std::io::stdout().lock(), &loaded)),
        Command::Config {
            action: ConfigAction::Ls,
        } => emit(print_sources(&mut std::io::stdout().lock(), &loaded)),
        Command::Config {
            action: ConfigAction::Init { .. },
        } => unreachable!("handled before loading"),
        Command::Scan { json, explain } => {
            let mut text = String::new();
            if let Err(e) = std::io::stdin().read_to_string(&mut text) {
                return fail(&format!("cannot read stdin: {e}"));
            }
            let spans = match scan::scan(&text, &loaded) {
                Ok(s) => s,
                Err(e) => return fail(&e),
            };
            if explain {
                for s in &spans {
                    eprintln!("{}:{} -> [{}-…]", s.pack, s.rule, s.label);
                }
            }
            let out = if json {
                serde_json::to_string_pretty(&spans).expect("spans serialise") + "\n"
            } else {
                match scan::Tagger::new(std::env::var("REDACT_KEY").ok().as_deref()) {
                    Ok(mut tagger) => scan::mask(&text, &spans, &mut tagger),
                    Err(e) => {
                        eprintln!("redact: {e}");
                        return ExitCode::from(2);
                    }
                }
            };
            // Flushed here: an error writing the last line at exit would go unseen.
            let mut stdout = std::io::stdout();
            emit(
                stdout
                    .write_all(out.as_bytes())
                    .and_then(|()| stdout.flush()),
            )
        }
        Command::Completions { .. } | Command::Init { .. } => unreachable!("handled above"),
    }
}

// A reader that stops early (`redact packs | head`) is not a failure.
fn emit(written: std::io::Result<()>) -> ExitCode {
    match written {
        Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => {
            fail(&format!("cannot write stdout: {e}"))
        }
        _ => ExitCode::SUCCESS,
    }
}

fn fail(message: &str) -> ExitCode {
    eprintln!("redact: {message}");
    ExitCode::from(3)
}

fn print_packs(w: &mut impl Write, loaded: &pack::Loaded) -> std::io::Result<()> {
    let all = loaded.packs.iter().map(|p| (p, "")).chain(
        loaded
            .off
            .iter()
            .map(|p| (p, ", off: turn on with [packs] enable")),
    );
    for (p, off) in all {
        writeln!(w, "{}  {} rules  ({}{off})", p.id, p.rules.len(), p.source)?;
        if !p.description.is_empty() {
            writeln!(w, "  {}", p.description)?;
        }
        for r in &p.rules {
            writeln!(w, "  {:<24} [{}-…]  {}", r.id, r.label, r.description)?;
        }
        if !p.allow_as_written.is_empty() {
            writeln!(
                w,
                "  allowed (never hidden): {}",
                p.allow_as_written.join(", ")
            )?;
        }
    }
    for list in &loaded.words {
        writeln!(
            w,
            "words  {} entries as [{}-…]  ({})",
            list.words.len(),
            list.label,
            list.source
        )?;
    }
    if let Some(home) = pack::config_home() {
        writeln!(
            w,
            "\nYour config: {}  (redact config ls shows every file)",
            pack::tilde(&home.join("config.toml"))
        )?;
    }
    Ok(())
}

fn print_sources(w: &mut impl Write, loaded: &pack::Loaded) -> std::io::Result<()> {
    let width = loaded
        .sources
        .iter()
        .map(|s| s.path.chars().count())
        .max()
        .unwrap_or(0);
    for (i, s) in loaded.sources.iter().enumerate() {
        let via = s
            .via
            .as_deref()
            .map(|v| format!("  <- {v}"))
            .unwrap_or_default();
        writeln!(
            w,
            "{:>2}  {:<7} {:<width$}  {}{via}",
            i + 1,
            s.kind,
            s.path,
            s.detail
        )?;
    }
    Ok(())
}

/// The reference pages in docs/ are generated from the code, so they cannot
/// drift: this test fails when one is out of date, and `REDACT_BLESS=1 cargo test`
/// rewrites them.
#[cfg(test)]
mod docs {
    use super::*;

    const NOTE: &str =
        "<!-- Generated by `REDACT_BLESS=1 cargo test` from the code. Do not edit by hand. -->";

    /// A table cell: `|` would end the cell, and VitePress reads `<name>` as a tag.
    fn cell(s: &str) -> String {
        s.replace('|', "\\|")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }

    fn pack_page(p: &pack::Pack) -> String {
        let mut out = format!("# `{}` pack\n\n{NOTE}\n\n{}\n\n", p.id, p.description);
        out.push_str("| Rule | Hides as | What it finds | Hidden everywhere after |\n| :- | :- | :- | :- |\n");
        for r in &p.rules {
            let remember = match r.remember {
                pack::Remember::No => "",
                pack::Remember::Distinctive => "when it reads as a name",
                pack::Remember::Any => "yes",
            };
            out.push_str(&format!(
                "| `{}` | `[{}-…]` | {} | {} |\n",
                r.id,
                r.label,
                cell(&r.description),
                remember
            ));
        }
        if !p.allow_as_written.is_empty() {
            let list: Vec<String> = p
                .allow_as_written
                .iter()
                .map(|a| format!("`{a}`"))
                .collect();
            out.push_str(&format!(
                "\n## Allowed values\n\nThese exact values are left alone even when a rule above would hide them: they are settings or public names, not secrets. Only the value itself is allowed, never what sits next to it.\n\n{}\n",
                list.join(", ")
            ));
        }
        out
    }

    fn cli_page() -> String {
        let mut root = Cli::command();
        let mut out = format!(
            "# CLI reference\n\n{NOTE}\n\n## `redact`\n\n```text\n{}```\n",
            root.render_long_help()
        );
        let names: Vec<String> = root
            .get_subcommands()
            .map(|c| c.get_name().to_string())
            .filter(|n| n != "help")
            .collect();
        for name in names {
            let sub = root.find_subcommand_mut(&name).expect("listed above");
            out.push_str(&format!(
                "\n## `redact {name}`\n\n```text\n{}```\n",
                sub.render_long_help()
            ));
        }
        out
    }

    /// Every shell `redact init` accepts gets a `redacted` helper, and the bash
    /// one pipes stderr through `redact scan` and keeps the command's status.
    #[test]
    fn init_gives_every_shell_a_helper() {
        use clap::ValueEnum;
        for shell in clap_complete::Shell::value_variants() {
            assert!(init_helper(*shell).contains("redacted"), "{shell}");
        }
        if cfg!(not(unix)) {
            return;
        }
        let dir = std::env::temp_dir().join(format!("redact-init-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // A stand-in redact that tags each line it is given.
        let stub = dir.join("redact");
        std::fs::write(&stub, "#!/bin/sh\nsed 's/^/scanned:/'\n").unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&stub, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();
        let script = format!(
            "{}redacted sh -c 'echo out; echo err >&2; exit 3'; echo \"status=$?\"",
            init_helper(clap_complete::Shell::Bash)
        );
        let Ok(out) = std::process::Command::new("bash")
            .arg("-c")
            .arg(script)
            .env("PATH", format!("{}:/usr/bin:/bin", dir.display()))
            .output()
        else {
            return; // no bash on this machine
        };
        std::fs::remove_dir_all(&dir).ok();
        let out = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.contains("scanned:out") && out.contains("scanned:err"),
            "{out}"
        );
        assert!(out.contains("status=3"), "{out}");
    }

    /// The minimal and full presets load as written, and full turns pii on.
    #[test]
    fn the_live_presets_load() {
        for (name, text) in [("minimal", MINIMAL_CONFIG), ("full", FULL_CONFIG)] {
            let d = std::env::temp_dir().join(format!("redact-test-{}-{name}", std::process::id()));
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("config.toml"), text).unwrap();
            let loaded = pack::load(&pack::Options {
                files: vec![],
                builtin: true,
                user: true,
                config: Some(d.join("config.toml")),
                env_files: vec![],
                command: None,
                cwd: Some(d.clone()),
                host: None,
            });
            std::fs::remove_dir_all(&d).unwrap();
            let loaded = loaded.unwrap_or_else(|e| panic!("{name} preset: {e}"));
            assert_eq!(
                loaded.packs.iter().any(|p| p.id == "pii"),
                name == "full",
                "{name}: pii"
            );
        }
    }

    /// Every example in the starter config, uncommented, loads: the starter can
    /// never show a setting that does not parse or a pack that does not exist.
    #[test]
    fn the_starter_config_examples_all_load() {
        let setting = regex::Regex::new(r"^# (\[|[a-z_]+ = )").unwrap();
        let live: String = STARTER_CONFIG
            .lines()
            .map(|l| if setting.is_match(l) { &l[2..] } else { l })
            .collect::<Vec<_>>()
            .join("\n");
        let d = std::env::temp_dir().join(format!("redact-test-{}-starter", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("packs")).unwrap();
        std::fs::write(d.join("customers.txt"), "Contoso Pharma\n").unwrap();
        std::fs::write(d.join("config.toml"), &live).unwrap();
        let loaded = pack::load(&pack::Options {
            files: vec![],
            builtin: true,
            user: true,
            config: Some(d.join("config.toml")),
            env_files: vec![],
            command: Some("gh pr view 42".into()),
            cwd: Some(d.clone()),
            host: Some("work-laptop".into()),
        });
        std::fs::remove_dir_all(&d).unwrap();
        let loaded = loaded.expect("the uncommented starter config loads");
        assert!(
            loaded.sources.iter().any(|s| s.kind == "override"),
            "no override applied"
        );
        assert!(
            STARTER_CONFIG
                .lines()
                .filter(|l| setting.is_match(l))
                .count()
                >= 10
        );
    }

    #[test]
    fn docs_are_current() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs");
        let loaded = pack::load(&pack::Options {
            files: vec![],
            builtin: true,
            user: false,
            config: None,
            env_files: vec![],
            command: None,
            cwd: None,
            host: None,
        })
        .expect("built-in packs load");
        let mut pages = vec![(root.join("reference/cli.md"), cli_page())];
        for p in loaded.packs.iter().chain(&loaded.off) {
            pages.push((root.join(format!("packs/{}.md", p.id)), pack_page(p)));
        }
        let bless = std::env::var_os("REDACT_BLESS").is_some();
        let mut stale = Vec::new();
        for (path, want) in pages {
            let have = std::fs::read_to_string(&path).unwrap_or_default();
            if have != want {
                if bless {
                    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                    std::fs::write(&path, want).unwrap();
                } else {
                    stale.push(path.display().to_string());
                }
            }
        }
        assert!(
            stale.is_empty(),
            "out of date (run REDACT_BLESS=1 cargo test): {stale:?}"
        );
    }
}
