//! Sniff configuration loaded from environment variables and CLI args

use std::env;
use std::path::PathBuf;

/// AI provider selection
#[derive(Debug, Clone, PartialEq)]
pub enum AiProvider {
    /// OpenAI-compatible API (works with OpenAI, Ollama, vLLM, etc.)
    OpenAi,
    /// Local inference via Candle (requires `ml` feature)
    Candle,
}

impl std::str::FromStr for AiProvider {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "candle" => AiProvider::Candle,
            // "ollama" uses the same OpenAI-compatible API client
            "openai" | "ollama" => AiProvider::OpenAi,
            _ => AiProvider::OpenAi,
        })
    }
}

/// Configuration for the `stackdog sniff` command
#[derive(Debug, Clone)]
pub struct SniffConfig {
    /// Run once then exit (vs continuous daemon mode)
    pub once: bool,
    /// Enable consume mode: archive + purge originals
    pub consume: bool,
    /// Output directory for archived/consumed logs
    pub output_dir: PathBuf,
    /// Additional log source paths (user-configured)
    pub extra_sources: Vec<String>,
    /// Explicit file or directory paths to monitor for integrity drift
    pub integrity_paths: Vec<String>,
    /// Explicit config files to audit for insecure settings
    pub config_assessment_paths: Vec<String>,
    /// Explicit package inventory files to audit for legacy versions
    pub package_inventory_paths: Vec<String>,
    /// Poll interval in seconds
    pub interval_secs: u64,
    /// AI provider to use for summarization
    pub ai_provider: AiProvider,
    /// AI API URL (for OpenAI-compatible providers)
    pub ai_api_url: String,
    /// AI API key (optional for local providers like Ollama)
    pub ai_api_key: Option<String>,
    /// AI model name
    pub ai_model: String,
    /// Database URL
    pub database_url: String,
    /// Slack webhook URL for alert notifications
    pub slack_webhook: Option<String>,
    /// Generic webhook URL for alert notifications
    pub webhook_url: Option<String>,
    /// SMTP host for email notifications
    pub smtp_host: Option<String>,
    /// SMTP port for email notifications
    pub smtp_port: Option<u16>,
    /// SMTP username / sender address for email notifications
    pub smtp_user: Option<String>,
    /// SMTP password for email notifications
    pub smtp_password: Option<String>,
    /// Email recipients for alert notifications
    pub email_recipients: Vec<String>,
}

/// Arguments for building a SniffConfig
pub struct SniffArgs<'a> {
    pub once: bool,
    pub consume: bool,
    pub output: &'a str,
    pub sources: Option<&'a str>,
    pub interval: u64,
    pub ai_provider: Option<&'a str>,
    pub ai_model: Option<&'a str>,
    pub ai_api_url: Option<&'a str>,
    pub slack_webhook: Option<&'a str>,
    pub webhook_url: Option<&'a str>,
    pub smtp_host: Option<&'a str>,
    pub smtp_port: Option<u16>,
    pub smtp_user: Option<&'a str>,
    pub smtp_password: Option<&'a str>,
    pub email_recipients: Option<&'a str>,
}

impl SniffConfig {
    /// Build a continuous sniff config for the `stackdog serve` background worker.
    ///
    /// Serve mode defaults to the local pattern analyzer so log monitoring and
    /// IP bans still work even when no external AI backend is configured.
    pub fn background_service() -> Self {
        let ai_provider = env::var("STACKDOG_AI_PROVIDER").unwrap_or_else(|_| "candle".into());

        Self::from_env_and_args(SniffArgs {
            once: false,
            consume: false,
            output: "./stackdog-logs/",
            sources: None,
            interval: 30,
            ai_provider: Some(ai_provider.as_str()),
            ai_model: None,
            ai_api_url: None,
            slack_webhook: None,
            webhook_url: None,
            smtp_host: None,
            smtp_port: None,
            smtp_user: None,
            smtp_password: None,
            email_recipients: None,
        })
    }

    /// Build config from environment variables, overridden by CLI args
    pub fn from_env_and_args(args: SniffArgs<'_>) -> Self {
        let env_sources = env::var("STACKDOG_LOG_SOURCES").unwrap_or_default();
        let mut extra_sources: Vec<String> = env_sources
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        if let Some(cli_sources) = args.sources {
            for s in cli_sources.split(',') {
                let trimmed = s.trim().to_string();
                if !trimmed.is_empty() && !extra_sources.contains(&trimmed) {
                    extra_sources.push(trimmed);
                }
            }
        }

        let integrity_paths = env::var("STACKDOG_FIM_PATHS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let config_assessment_paths = env::var("STACKDOG_SCA_PATHS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let package_inventory_paths = env::var("STACKDOG_PACKAGE_INVENTORY_PATHS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let ai_provider_str = args.ai_provider.map(|s| s.to_string()).unwrap_or_else(|| {
            env::var("STACKDOG_AI_PROVIDER").unwrap_or_else(|_| "openai".into())
        });

        let output_dir = if args.output != "./stackdog-logs/" {
            PathBuf::from(args.output)
        } else {
            PathBuf::from(
                env::var("STACKDOG_SNIFF_OUTPUT_DIR").unwrap_or_else(|_| args.output.to_string()),
            )
        };

        let interval_secs = if args.interval != 30 {
            args.interval
        } else {
            env::var("STACKDOG_SNIFF_INTERVAL")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(args.interval)
        };

        Self {
            once: args.once,
            consume: args.consume,
            output_dir,
            extra_sources,
            integrity_paths,
            config_assessment_paths,
            package_inventory_paths,
            interval_secs,
            ai_provider: ai_provider_str.parse().unwrap(),
            ai_api_url: args
                .ai_api_url
                .map(|s| s.to_string())
                .or_else(|| env::var("STACKDOG_AI_API_URL").ok())
                .unwrap_or_else(|| "http://localhost:11434/v1".into()),
            ai_api_key: env::var("STACKDOG_AI_API_KEY").ok(),
            ai_model: args
                .ai_model
                .map(|s| s.to_string())
                .or_else(|| env::var("STACKDOG_AI_MODEL").ok())
                .unwrap_or_else(|| "llama3".into()),
            database_url: env::var("DATABASE_URL").unwrap_or_else(|_| "./stackdog.db".into()),
            slack_webhook: args
                .slack_webhook
                .map(|s| s.to_string())
                .or_else(|| env::var("STACKDOG_SLACK_WEBHOOK_URL").ok()),
            webhook_url: args
                .webhook_url
                .map(|s| s.to_string())
                .or_else(|| env::var("STACKDOG_WEBHOOK_URL").ok()),
            smtp_host: args
                .smtp_host
                .map(|s| s.to_string())
                .or_else(|| env::var("STACKDOG_SMTP_HOST").ok()),
            smtp_port: args.smtp_port.or_else(|| {
                env::var("STACKDOG_SMTP_PORT")
                    .ok()
                    .and_then(|v| v.parse().ok())
            }),
            smtp_user: args
                .smtp_user
                .map(|s| s.to_string())
                .or_else(|| env::var("STACKDOG_SMTP_USER").ok()),
            smtp_password: args
                .smtp_password
                .map(|s| s.to_string())
                .or_else(|| env::var("STACKDOG_SMTP_PASSWORD").ok()),
            email_recipients: args
                .email_recipients
                .map(|s| s.to_string())
                .or_else(|| env::var("STACKDOG_EMAIL_RECIPIENTS").ok())
                .map(|recipients| {
                    recipients
                        .split(',')
                        .map(|recipient| recipient.trim().to_string())
                        .filter(|recipient| !recipient.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serialize env-mutating tests to avoid cross-contamination
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    fn clear_sniff_env() {
        env::remove_var("STACKDOG_LOG_SOURCES");
        env::remove_var("STACKDOG_FIM_PATHS");
        env::remove_var("STACKDOG_SCA_PATHS");
        env::remove_var("STACKDOG_PACKAGE_INVENTORY_PATHS");
        env::remove_var("STACKDOG_AI_PROVIDER");
        env::remove_var("STACKDOG_AI_API_URL");
        env::remove_var("STACKDOG_AI_API_KEY");
        env::remove_var("STACKDOG_AI_MODEL");
        env::remove_var("STACKDOG_SNIFF_OUTPUT_DIR");
        env::remove_var("STACKDOG_SNIFF_INTERVAL");
        env::remove_var("STACKDOG_SLACK_WEBHOOK_URL");
        env::remove_var("STACKDOG_WEBHOOK_URL");
        env::remove_var("STACKDOG_SMTP_HOST");
        env::remove_var("STACKDOG_SMTP_PORT");
        env::remove_var("STACKDOG_SMTP_USER");
        env::remove_var("STACKDOG_SMTP_PASSWORD");
        env::remove_var("STACKDOG_EMAIL_RECIPIENTS");
    }

    #[test]
    fn test_ai_provider_from_str() {
        assert_eq!("openai".parse::<AiProvider>().unwrap(), AiProvider::OpenAi);
        assert_eq!("OpenAI".parse::<AiProvider>().unwrap(), AiProvider::OpenAi);
        assert_eq!("candle".parse::<AiProvider>().unwrap(), AiProvider::Candle);
        assert_eq!("Candle".parse::<AiProvider>().unwrap(), AiProvider::Candle);
        assert_eq!("unknown".parse::<AiProvider>().unwrap(), AiProvider::OpenAi);
    }

    #[test]
    fn test_sniff_config_defaults() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_sniff_env();

        let config = SniffConfig::from_env_and_args(SniffArgs {
            once: false,
            consume: false,
            output: "./stackdog-logs/",
            sources: None,
            interval: 30,
            ai_provider: None,
            ai_model: None,
            ai_api_url: None,
            slack_webhook: None,
            webhook_url: None,
            smtp_host: None,
            smtp_port: None,
            smtp_user: None,
            smtp_password: None,
            email_recipients: None,
        });
        assert!(!config.once);
        assert!(!config.consume);
        assert_eq!(config.output_dir, PathBuf::from("./stackdog-logs/"));
        assert!(config.extra_sources.is_empty());
        assert!(config.integrity_paths.is_empty());
        assert!(config.config_assessment_paths.is_empty());
        assert!(config.package_inventory_paths.is_empty());
        assert_eq!(config.interval_secs, 30);
        assert_eq!(config.ai_provider, AiProvider::OpenAi);
        assert_eq!(config.ai_api_url, "http://localhost:11434/v1");
        assert!(config.ai_api_key.is_none());
        assert_eq!(config.ai_model, "llama3");
    }

    #[test]
    fn test_background_service_defaults_to_pattern_analyzer() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_sniff_env();

        let config = SniffConfig::background_service();
        assert!(!config.once);
        assert!(!config.consume);
        assert_eq!(config.interval_secs, 30);
        assert_eq!(config.ai_provider, AiProvider::Candle);
    }

    #[test]
    fn test_background_service_respects_env_ai_provider() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_sniff_env();
        env::set_var("STACKDOG_AI_PROVIDER", "openai");

        let config = SniffConfig::background_service();
        assert_eq!(config.ai_provider, AiProvider::OpenAi);
    }

    #[test]
    fn test_sniff_config_cli_overrides() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_sniff_env();

        let config = SniffConfig::from_env_and_args(SniffArgs {
            once: true,
            consume: true,
            output: "/tmp/output/",
            sources: Some("/var/log/app.log"),
            interval: 60,
            ai_provider: Some("candle"),
            ai_model: None,
            ai_api_url: None,
            slack_webhook: None,
            webhook_url: None,
            smtp_host: None,
            smtp_port: None,
            smtp_user: None,
            smtp_password: None,
            email_recipients: None,
        });

        assert!(config.once);
        assert!(config.consume);
        assert_eq!(config.output_dir, PathBuf::from("/tmp/output/"));
        assert_eq!(config.extra_sources, vec!["/var/log/app.log"]);
        assert_eq!(config.interval_secs, 60);
        assert_eq!(config.ai_provider, AiProvider::Candle);
    }

    #[test]
    fn test_sniff_config_env_sources_merged_with_cli() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_sniff_env();
        env::set_var("STACKDOG_LOG_SOURCES", "/var/log/syslog,/var/log/auth.log");

        let config = SniffConfig::from_env_and_args(SniffArgs {
            once: false,
            consume: false,
            output: "./stackdog-logs/",
            sources: Some("/var/log/app.log,/var/log/syslog"),
            interval: 30,
            ai_provider: None,
            ai_model: None,
            ai_api_url: None,
            slack_webhook: None,
            webhook_url: None,
            smtp_host: None,
            smtp_port: None,
            smtp_user: None,
            smtp_password: None,
            email_recipients: None,
        });

        assert!(config
            .extra_sources
            .contains(&"/var/log/syslog".to_string()));
        assert!(config
            .extra_sources
            .contains(&"/var/log/auth.log".to_string()));
        assert!(config
            .extra_sources
            .contains(&"/var/log/app.log".to_string()));
        assert_eq!(config.extra_sources.len(), 3);

        clear_sniff_env();
    }

    #[test]
    fn test_sniff_config_fim_paths_from_env() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_sniff_env();
        env::set_var("STACKDOG_FIM_PATHS", "/etc/ssh/sshd_config, /app/.env");

        let config = SniffConfig::from_env_and_args(SniffArgs {
            once: false,
            consume: false,
            output: "./stackdog-logs/",
            sources: None,
            interval: 30,
            ai_provider: None,
            ai_model: None,
            ai_api_url: None,
            slack_webhook: None,
            webhook_url: None,
            smtp_host: None,
            smtp_port: None,
            smtp_user: None,
            smtp_password: None,
            email_recipients: None,
        });

        assert_eq!(
            config.integrity_paths,
            vec!["/etc/ssh/sshd_config".to_string(), "/app/.env".to_string()]
        );

        clear_sniff_env();
    }

    #[test]
    fn test_sniff_config_audit_paths_from_env() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_sniff_env();
        env::set_var("STACKDOG_SCA_PATHS", "/etc/ssh/sshd_config,/etc/sudoers");
        env::set_var(
            "STACKDOG_PACKAGE_INVENTORY_PATHS",
            "/var/lib/dpkg/status,/lib/apk/db/installed",
        );

        let config = SniffConfig::from_env_and_args(SniffArgs {
            once: false,
            consume: false,
            output: "./stackdog-logs/",
            sources: None,
            interval: 30,
            ai_provider: None,
            ai_model: None,
            ai_api_url: None,
            slack_webhook: None,
            webhook_url: None,
            smtp_host: None,
            smtp_port: None,
            smtp_user: None,
            smtp_password: None,
            email_recipients: None,
        });

        assert_eq!(
            config.config_assessment_paths,
            vec![
                "/etc/ssh/sshd_config".to_string(),
                "/etc/sudoers".to_string()
            ]
        );
        assert_eq!(
            config.package_inventory_paths,
            vec![
                "/var/lib/dpkg/status".to_string(),
                "/lib/apk/db/installed".to_string()
            ]
        );

        clear_sniff_env();
    }

    #[test]
    fn test_sniff_config_env_overrides_defaults() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_sniff_env();
        env::set_var("STACKDOG_AI_API_URL", "https://api.openai.com/v1");
        env::set_var("STACKDOG_AI_API_KEY", "sk-test123");
        env::set_var("STACKDOG_AI_MODEL", "gpt-4o-mini");
        env::set_var("STACKDOG_SNIFF_INTERVAL", "45");
        env::set_var("STACKDOG_SNIFF_OUTPUT_DIR", "/data/logs/");

        let config = SniffConfig::from_env_and_args(SniffArgs {
            once: false,
            consume: false,
            output: "./stackdog-logs/",
            sources: None,
            interval: 30,
            ai_provider: None,
            ai_model: None,
            ai_api_url: None,
            slack_webhook: None,
            webhook_url: None,
            smtp_host: None,
            smtp_port: None,
            smtp_user: None,
            smtp_password: None,
            email_recipients: None,
        });
        assert_eq!(config.ai_api_url, "https://api.openai.com/v1");
        assert_eq!(config.ai_api_key, Some("sk-test123".into()));
        assert_eq!(config.ai_model, "gpt-4o-mini");
        assert_eq!(config.interval_secs, 45);
        assert_eq!(config.output_dir, PathBuf::from("/data/logs/"));

        clear_sniff_env();
    }

    #[test]
    fn test_ollama_provider_alias() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_sniff_env();

        let config = SniffConfig::from_env_and_args(SniffArgs {
            once: false,
            consume: false,
            output: "./stackdog-logs/",
            sources: None,
            interval: 30,
            ai_provider: Some("ollama"),
            ai_model: Some("qwen2.5-coder:latest"),
            ai_api_url: None,
            slack_webhook: None,
            webhook_url: None,
            smtp_host: None,
            smtp_port: None,
            smtp_user: None,
            smtp_password: None,
            email_recipients: None,
        });
        // "ollama" maps to OpenAi internally (same API protocol)
        assert_eq!(config.ai_provider, AiProvider::OpenAi);
        assert_eq!(config.ai_model, "qwen2.5-coder:latest");
        assert_eq!(config.ai_api_url, "http://localhost:11434/v1");

        clear_sniff_env();
    }

    #[test]
    fn test_cli_args_override_env_vars() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_sniff_env();
        env::set_var("STACKDOG_AI_MODEL", "gpt-4o-mini");
        env::set_var("STACKDOG_AI_API_URL", "https://api.openai.com/v1");

        let config = SniffConfig::from_env_and_args(SniffArgs {
            once: false,
            consume: false,
            output: "./stackdog-logs/",
            sources: None,
            interval: 30,
            ai_provider: None,
            ai_model: Some("llama3"),
            ai_api_url: Some("http://localhost:11434/v1"),
            slack_webhook: None,
            webhook_url: None,
            smtp_host: None,
            smtp_port: None,
            smtp_user: None,
            smtp_password: None,
            email_recipients: None,
        });
        // CLI args take priority over env vars
        assert_eq!(config.ai_model, "llama3");
        assert_eq!(config.ai_api_url, "http://localhost:11434/v1");

        clear_sniff_env();
    }

    #[test]
    fn test_slack_webhook_from_cli() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_sniff_env();

        let config = SniffConfig::from_env_and_args(SniffArgs {
            once: false,
            consume: false,
            output: "./stackdog-logs/",
            sources: None,
            interval: 30,
            ai_provider: None,
            ai_model: None,
            ai_api_url: None,
            slack_webhook: Some("https://hooks.slack.com/services/T/B/xxx"),
            webhook_url: None,
            smtp_host: None,
            smtp_port: None,
            smtp_user: None,
            smtp_password: None,
            email_recipients: None,
        });
        assert_eq!(
            config.slack_webhook.as_deref(),
            Some("https://hooks.slack.com/services/T/B/xxx")
        );

        clear_sniff_env();
    }

    #[test]
    fn test_slack_webhook_from_env() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_sniff_env();
        env::set_var(
            "STACKDOG_SLACK_WEBHOOK_URL",
            "https://hooks.slack.com/services/T/B/env",
        );

        let config = SniffConfig::from_env_and_args(SniffArgs {
            once: false,
            consume: false,
            output: "./stackdog-logs/",
            sources: None,
            interval: 30,
            ai_provider: None,
            ai_model: None,
            ai_api_url: None,
            slack_webhook: None,
            webhook_url: None,
            smtp_host: None,
            smtp_port: None,
            smtp_user: None,
            smtp_password: None,
            email_recipients: None,
        });
        assert_eq!(
            config.slack_webhook.as_deref(),
            Some("https://hooks.slack.com/services/T/B/env")
        );

        clear_sniff_env();
    }

    #[test]
    fn test_slack_webhook_cli_overrides_env() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_sniff_env();
        env::set_var(
            "STACKDOG_SLACK_WEBHOOK_URL",
            "https://hooks.slack.com/services/T/B/env",
        );

        let config = SniffConfig::from_env_and_args(SniffArgs {
            once: false,
            consume: false,
            output: "./stackdog-logs/",
            sources: None,
            interval: 30,
            ai_provider: None,
            ai_model: None,
            ai_api_url: None,
            slack_webhook: Some("https://hooks.slack.com/services/T/B/cli"),
            webhook_url: None,
            smtp_host: None,
            smtp_port: None,
            smtp_user: None,
            smtp_password: None,
            email_recipients: None,
        });
        assert_eq!(
            config.slack_webhook.as_deref(),
            Some("https://hooks.slack.com/services/T/B/cli")
        );

        clear_sniff_env();
    }

    #[test]
    fn test_notification_channels_from_env() {
        let _lock = ENV_MUTEX.lock().unwrap();
        clear_sniff_env();
        env::set_var(
            "STACKDOG_WEBHOOK_URL",
            "https://example.test/hooks/stackdog",
        );
        env::set_var("STACKDOG_SMTP_HOST", "smtp.example.com");
        env::set_var("STACKDOG_SMTP_PORT", "2525");
        env::set_var("STACKDOG_SMTP_USER", "alerts@example.com");
        env::set_var("STACKDOG_SMTP_PASSWORD", "secret");
        env::set_var(
            "STACKDOG_EMAIL_RECIPIENTS",
            "soc@example.com, oncall@example.com",
        );

        let config = SniffConfig::from_env_and_args(SniffArgs {
            once: false,
            consume: false,
            output: "./stackdog-logs/",
            sources: None,
            interval: 30,
            ai_provider: None,
            ai_model: None,
            ai_api_url: None,
            slack_webhook: None,
            webhook_url: None,
            smtp_host: None,
            smtp_port: None,
            smtp_user: None,
            smtp_password: None,
            email_recipients: None,
        });

        assert_eq!(
            config.webhook_url.as_deref(),
            Some("https://example.test/hooks/stackdog")
        );
        assert_eq!(config.smtp_host.as_deref(), Some("smtp.example.com"));
        assert_eq!(config.smtp_port, Some(2525));
        assert_eq!(config.smtp_user.as_deref(), Some("alerts@example.com"));
        assert_eq!(config.smtp_password.as_deref(), Some("secret"));
        assert_eq!(
            config.email_recipients,
            vec![
                "soc@example.com".to_string(),
                "oncall@example.com".to_string()
            ]
        );

        clear_sniff_env();
    }
}
