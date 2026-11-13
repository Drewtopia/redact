//! redact: keep secrets, names and work details out of what AI agents see.
//!
//! Exit codes: 0 done, 2 bad usage, 3 a pack would not load or the scan failed.

mod pack;
mod scan;

use clap::{CommandFactory, Parser, Subcommand};
use std::io::{IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;

/// Keep secrets, names and work details out of what AI agents see.
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
