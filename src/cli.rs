//! CLI argument parsing for Stackdog
//!
//! Defines the command-line interface using clap derive macros.
//! Supports `serve` (HTTP server) and `sniff` (log analysis) subcommands.

use clap::{Args, Parser, Subcommand};

const VERSION: &str = concat!(
    env!("CARGO_PKG_VERSION"),
    " (",
    env!("STACKDOG_GIT_HASH"),
    ")"
);

/// Stackdog Security — Docker & Linux server security platform
#[derive(Parser, Debug)]
#[command(name = "stackdog", version = VERSION, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

/// Available subcommands
#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Start the HTTP API server (default behavior)
    Serve,

    /// Sniff and analyze logs from Docker containers and system sources
    Sniff(Box<SniffCommand>),
}

#[derive(Args, Debug, Clone)]
pub struct SniffCommand {
    /// Run a single scan/analysis pass, then exit
    #[arg(long)]
    pub once: bool,

    /// Consume logs: archive to zstd, then purge originals to free disk
    #[arg(long)]
    pub consume: bool,

    /// Output directory for consumed logs
    #[arg(long, default_value = "./stackdog-logs/")]
    pub output: String,

    /// Additional log file paths to watch (comma-separated)
    #[arg(long)]
    pub sources: Option<String>,

    /// Poll interval in seconds
    #[arg(long, default_value = "30")]
    pub interval: u64,

    /// AI provider: "openai", "ollama", or "candle"
    #[arg(long)]
    pub ai_provider: Option<String>,

    /// AI model name (e.g. "gpt-4o-mini", "qwen2.5-coder:latest", "llama3")
    #[arg(long)]
    pub ai_model: Option<String>,

    /// AI API URL (e.g. "http://localhost:11434/v1" for Ollama)
    #[arg(long)]
    pub ai_api_url: Option<String>,

    /// Slack webhook URL for alert notifications
    #[arg(long)]
    pub slack_webhook: Option<String>,

    /// Generic webhook URL for alert notifications
    #[arg(long)]
    pub webhook_url: Option<String>,

    /// SMTP host for email alert notifications
    #[arg(long)]
    pub smtp_host: Option<String>,

    /// SMTP port for email alert notifications
    #[arg(long)]
    pub smtp_port: Option<u16>,

    /// SMTP username / sender address for email alert notifications
    #[arg(long)]
    pub smtp_user: Option<String>,

    /// SMTP password for email alert notifications
    #[arg(long)]
    pub smtp_password: Option<String>,

    /// Comma-separated email recipients for alert notifications
    #[arg(long)]
    pub email_recipients: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn test_no_subcommand_defaults_to_none() {
        let cli = Cli::parse_from(["stackdog"]);
        assert!(
            cli.command.is_none(),
            "No subcommand should yield None (default to serve)"
        );
    }

    #[test]
    fn test_serve_subcommand() {
        let cli = Cli::parse_from(["stackdog", "serve"]);
        assert!(matches!(cli.command, Some(Command::Serve)));
    }

    #[test]
    fn test_sniff_subcommand_defaults() {
        let cli = Cli::parse_from(["stackdog", "sniff"]);
        match cli.command {
            Some(Command::Sniff(sniff)) => {
                let SniffCommand {
                    once,
                    consume,
                    output,
                    sources,
                    interval,
                    ai_provider,
                    ai_model,
                    ai_api_url,
                    slack_webhook,
                    webhook_url,
                    smtp_host,
                    smtp_port,
                    smtp_user,
                    smtp_password,
                    email_recipients,
                } = *sniff;
                assert!(!once);
                assert!(!consume);
                assert_eq!(output, "./stackdog-logs/");
                assert!(sources.is_none());
                assert_eq!(interval, 30);
                assert!(ai_provider.is_none());
                assert!(ai_model.is_none());
                assert!(ai_api_url.is_none());
                assert!(slack_webhook.is_none());
                assert!(webhook_url.is_none());
                assert!(smtp_host.is_none());
                assert!(smtp_port.is_none());
                assert!(smtp_user.is_none());
                assert!(smtp_password.is_none());
                assert!(email_recipients.is_none());
            }
            _ => panic!("Expected Sniff command"),
        }
    }

    #[test]
    fn test_sniff_with_once_flag() {
        let cli = Cli::parse_from(["stackdog", "sniff", "--once"]);
        match cli.command {
            Some(Command::Sniff(sniff)) => assert!(sniff.once),
            _ => panic!("Expected Sniff command"),
        }
    }

    #[test]
    fn test_sniff_with_consume_flag() {
        let cli = Cli::parse_from(["stackdog", "sniff", "--consume"]);
        match cli.command {
            Some(Command::Sniff(sniff)) => assert!(sniff.consume),
            _ => panic!("Expected Sniff command"),
        }
    }

    #[test]
    fn test_sniff_with_all_options() {
        let cli = Cli::parse_from([
            "stackdog",
            "sniff",
            "--once",
            "--consume",
            "--output",
            "/tmp/logs/",
            "--sources",
            "/var/log/syslog,/var/log/auth.log",
            "--interval",
            "60",
            "--ai-provider",
            "openai",
            "--ai-model",
            "gpt-4o-mini",
            "--ai-api-url",
            "https://api.openai.com/v1",
            "--slack-webhook",
            "https://hooks.slack.com/services/T/B/xxx",
            "--webhook-url",
            "https://example.com/hooks/stackdog",
            "--smtp-host",
            "smtp.example.com",
            "--smtp-port",
            "587",
            "--smtp-user",
            "alerts@example.com",
            "--smtp-password",
            "secret",
            "--email-recipients",
            "soc@example.com,oncall@example.com",
        ]);
        match cli.command {
            Some(Command::Sniff(sniff)) => {
                let SniffCommand {
                    once,
                    consume,
                    output,
                    sources,
                    interval,
                    ai_provider,
                    ai_model,
                    ai_api_url,
                    slack_webhook,
                    webhook_url,
                    smtp_host,
                    smtp_port,
                    smtp_user,
                    smtp_password,
                    email_recipients,
                } = *sniff;
                assert!(once);
                assert!(consume);
                assert_eq!(output, "/tmp/logs/");
                assert_eq!(sources.unwrap(), "/var/log/syslog,/var/log/auth.log");
                assert_eq!(interval, 60);
                assert_eq!(ai_provider.unwrap(), "openai");
                assert_eq!(ai_model.unwrap(), "gpt-4o-mini");
                assert_eq!(ai_api_url.unwrap(), "https://api.openai.com/v1");
                assert_eq!(
                    slack_webhook.unwrap(),
                    "https://hooks.slack.com/services/T/B/xxx"
                );
                assert_eq!(webhook_url.unwrap(), "https://example.com/hooks/stackdog");
                assert_eq!(smtp_host.unwrap(), "smtp.example.com");
                assert_eq!(smtp_port.unwrap(), 587);
                assert_eq!(smtp_user.unwrap(), "alerts@example.com");
                assert_eq!(smtp_password.unwrap(), "secret");
                assert_eq!(
                    email_recipients.unwrap(),
                    "soc@example.com,oncall@example.com"
                );
            }
            _ => panic!("Expected Sniff command"),
        }
    }

    #[test]
    fn test_sniff_with_candle_provider() {
        let cli = Cli::parse_from(["stackdog", "sniff", "--ai-provider", "candle"]);
        match cli.command {
            Some(Command::Sniff(sniff)) => {
                assert_eq!(sniff.ai_provider.as_deref(), Some("candle"));
            }
            _ => panic!("Expected Sniff command"),
        }
    }

    #[test]
    fn test_sniff_with_ollama_provider_and_model() {
        let cli = Cli::parse_from([
            "stackdog",
            "sniff",
            "--once",
            "--ai-provider",
            "ollama",
            "--ai-model",
            "qwen2.5-coder:latest",
        ]);
        match cli.command {
            Some(Command::Sniff(sniff)) => {
                assert_eq!(sniff.ai_provider.as_deref(), Some("ollama"));
                assert_eq!(sniff.ai_model.as_deref(), Some("qwen2.5-coder:latest"));
            }
            _ => panic!("Expected Sniff command"),
        }
    }
}
