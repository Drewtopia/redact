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
}

#[derive(Subcommand)]
enum ConfigAction {
    /// List every file that loads, in load order, and what imported it.
    Ls,
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
    if let Command::Completions { shell } = &command {
        clap_complete::generate(
            *shell,
            &mut Cli::command(),
            "redact",
            &mut std::io::stdout(),
        );
        return ExitCode::SUCCESS;
    }
    let opts = pack::Options {
        files: cli.files,
        builtin: !cli.only_files,
        user: !cli.only_files,
        config: cli.config,
        env_files: cli.env_files,
    };
    let loaded = match pack::load(&opts) {
        Ok(l) => l,
        Err(e) => return fail(&e),
    };
    match command {
        Command::Packs => {
            print_packs(&loaded);
            ExitCode::SUCCESS
        }
        Command::Config {
            action: ConfigAction::Ls,
        } => {
            print_sources(&loaded);
            ExitCode::SUCCESS
        }
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
            match std::io::stdout().write_all(out.as_bytes()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => fail(&format!("cannot write stdout: {e}")),
            }
        }
        Command::Completions { .. } => unreachable!("handled above"),
    }
}

fn fail(message: &str) -> ExitCode {
    eprintln!("redact: {message}");
    ExitCode::from(3)
}

fn print_packs(loaded: &pack::Loaded) {
    for p in &loaded.packs {
        println!("{}  {} rules  ({})", p.id, p.rules.len(), p.source);
        if !p.description.is_empty() {
            println!("  {}", p.description);
        }
        for r in &p.rules {
            println!("  {:<24} [{}-…]  {}", r.id, r.label, r.description);
        }
        if !p.allow_as_written.is_empty() {
            println!(
                "  allowed (never hidden): {}",
                p.allow_as_written.join(", ")
            );
        }
    }
    for w in &loaded.words {
        println!(
            "words  {} entries as [{}-…]  ({})",
            w.words.len(),
            w.label,
            w.source
        );
    }
    if let Some(home) = pack::config_home() {
        println!(
            "\nYour config: {}  (redact config ls shows every file)",
            pack::tilde(&home.join("config.toml"))
        );
    }
}

fn print_sources(loaded: &pack::Loaded) {
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
        println!(
            "{:>2}  {:<7} {:<width$}  {}{via}",
            i + 1,
            s.kind,
            s.path,
            s.detail
        );
    }
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

    #[test]
    fn docs_are_current() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs");
        let loaded = pack::load(&pack::Options {
            files: vec![],
            builtin: true,
            user: false,
            config: None,
            env_files: vec![],
        })
        .expect("built-in packs load");
        let mut pages = vec![(root.join("reference/cli.md"), cli_page())];
        for p in &loaded.packs {
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
