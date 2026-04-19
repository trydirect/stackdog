//! Alert notifications
//!
//! Notification channels for alert delivery

use anyhow::{Context, Result};
use lettre::message::{Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use std::env;

use crate::alerting::alert::{Alert, AlertSeverity};

/// Notification configuration
#[derive(Debug, Clone)]
pub struct NotificationConfig {
    slack_webhook: Option<String>,
    smtp_host: Option<String>,
    smtp_port: Option<u16>,
    smtp_user: Option<String>,
    smtp_password: Option<String>,
    webhook_url: Option<String>,
    email_recipients: Vec<String>,
    notification_label: Option<String>,
    minimum_severity: AlertSeverity,
}

impl NotificationConfig {
    /// Create default config
    pub fn new() -> Self {
        Self {
            slack_webhook: None,
            smtp_host: None,
            smtp_port: None,
            smtp_user: None,
            smtp_password: None,
            webhook_url: None,
            email_recipients: Vec::new(),
            notification_label: None,
            minimum_severity: AlertSeverity::Info,
        }
    }

    /// Build notification config from environment variables.
    pub fn from_env() -> Self {
        Self {
            slack_webhook: env::var("STACKDOG_SLACK_WEBHOOK_URL").ok(),
            smtp_host: env::var("STACKDOG_SMTP_HOST").ok(),
            smtp_port: env::var("STACKDOG_SMTP_PORT")
                .ok()
                .and_then(|value| value.parse().ok()),
            smtp_user: env::var("STACKDOG_SMTP_USER").ok(),
            smtp_password: env::var("STACKDOG_SMTP_PASSWORD").ok(),
            webhook_url: env::var("STACKDOG_WEBHOOK_URL").ok(),
            email_recipients: env::var("STACKDOG_EMAIL_RECIPIENTS")
                .ok()
                .map(|recipients| {
                    recipients
                        .split(',')
                        .map(|recipient| recipient.trim().to_string())
                        .filter(|recipient| !recipient.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            notification_label: env::var("STACKDOG_NOTIFICATION_LABEL").ok(),
            minimum_severity: env::var("STACKDOG_NOTIFICATION_MIN_SEVERITY")
                .ok()
                .and_then(|value| parse_alert_severity(&value))
                .unwrap_or(AlertSeverity::Info),
        }
    }

    /// Set Slack webhook
    pub fn with_slack_webhook(mut self, url: String) -> Self {
        self.slack_webhook = Some(url);
        self
    }

    /// Set SMTP host
    pub fn with_smtp_host(mut self, host: String) -> Self {
        self.smtp_host = Some(host);
        self
    }

    /// Set SMTP port
    pub fn with_smtp_port(mut self, port: u16) -> Self {
        self.smtp_port = Some(port);
        self
    }

    /// Set SMTP user
    pub fn with_smtp_user(mut self, user: String) -> Self {
        self.smtp_user = Some(user);
        self
    }

    /// Set SMTP password
    pub fn with_smtp_password(mut self, password: String) -> Self {
        self.smtp_password = Some(password);
        self
    }

    /// Set email recipients
    pub fn with_email_recipients(mut self, recipients: Vec<String>) -> Self {
        self.email_recipients = recipients;
        self
    }

    /// Set webhook URL
    pub fn with_webhook_url(mut self, url: String) -> Self {
        self.webhook_url = Some(url);
        self
    }

    /// Set notification label
    pub fn with_notification_label(mut self, label: String) -> Self {
        self.notification_label = Some(label);
        self
    }

    /// Set minimum severity for non-action notifications
    pub fn with_minimum_severity(mut self, severity: AlertSeverity) -> Self {
        self.minimum_severity = severity;
        self
    }

    /// Get Slack webhook
    pub fn slack_webhook(&self) -> Option<&str> {
        self.slack_webhook.as_deref()
    }

    /// Get SMTP host
    pub fn smtp_host(&self) -> Option<&str> {
        self.smtp_host.as_deref()
    }

    /// Get SMTP port
    pub fn smtp_port(&self) -> Option<u16> {
        self.smtp_port
    }

    /// Get SMTP user
    pub fn smtp_user(&self) -> Option<&str> {
        self.smtp_user.as_deref()
    }

    /// Get SMTP password
    pub fn smtp_password(&self) -> Option<&str> {
        self.smtp_password.as_deref()
    }

    /// Get email recipients
    pub fn email_recipients(&self) -> &[String] {
        &self.email_recipients
    }

    /// Get webhook URL
    pub fn webhook_url(&self) -> Option<&str> {
        self.webhook_url.as_deref()
    }

    /// Get notification label
    pub fn notification_label(&self) -> Option<&str> {
        self.notification_label.as_deref()
    }

    /// Get minimum severity for non-action notifications
    pub fn minimum_severity(&self) -> AlertSeverity {
        self.minimum_severity
    }

    /// Return only channels that are both policy-selected and actually configured.
    pub fn configured_channels_for_severity(
        &self,
        severity: AlertSeverity,
    ) -> Vec<NotificationChannel> {
        route_by_severity(severity)
            .into_iter()
            .filter(|channel| self.supports_channel(channel))
            .collect()
    }

    pub fn configured_channels_for_stored_alert(
        &self,
        alert: &crate::database::models::Alert,
    ) -> Vec<NotificationChannel> {
        if is_action_alert(alert) {
            return self.configured_action_channels();
        }

        if alert.severity < self.minimum_severity {
            return Vec::new();
        }

        self.configured_channels_for_severity(alert.severity)
    }

    fn configured_action_channels(&self) -> Vec<NotificationChannel> {
        [
            NotificationChannel::Console,
            NotificationChannel::Slack,
            NotificationChannel::Email,
            NotificationChannel::Webhook,
        ]
        .into_iter()
        .filter(|channel| self.supports_channel(channel))
        .collect()
    }

    fn supports_channel(&self, channel: &NotificationChannel) -> bool {
        match channel {
            NotificationChannel::Console => true,
            NotificationChannel::Slack => self.slack_webhook.is_some(),
            NotificationChannel::Webhook => self.webhook_url.is_some(),
            NotificationChannel::Email => {
                self.smtp_host.is_some()
                    && self.smtp_port.is_some()
                    && self.smtp_user.is_some()
                    && self.smtp_password.is_some()
                    && !self.email_recipients.is_empty()
            }
        }
    }
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self::new()
    }
}

pub fn env_flag_enabled(name: &str, default: bool) -> bool {
    env::var(name)
        .ok()
        .and_then(|value| match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        })
        .unwrap_or(default)
}

fn parse_alert_severity(value: &str) -> Option<AlertSeverity> {
    match value.trim().to_ascii_lowercase().as_str() {
        "info" => Some(AlertSeverity::Info),
        "low" => Some(AlertSeverity::Low),
        "medium" => Some(AlertSeverity::Medium),
        "high" => Some(AlertSeverity::High),
        "critical" => Some(AlertSeverity::Critical),
        _ => None,
    }
}

fn is_action_alert(alert: &crate::database::models::Alert) -> bool {
    matches!(
        alert.alert_type,
        crate::alerting::alert::AlertType::QuarantineApplied
    ) || alert
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.source.as_deref())
        .map(|source| matches!(source, "ip_ban" | "quarantine"))
        .unwrap_or(false)
}

/// Notification channel
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotificationChannel {
    Console,
    Slack,
    Email,
    Webhook,
}

impl NotificationChannel {
    /// Send notification
    pub async fn send(
        &self,
        alert: &Alert,
        config: &NotificationConfig,
    ) -> Result<NotificationResult> {
        match self {
            NotificationChannel::Console => self.send_console(alert),
            NotificationChannel::Slack => self.send_slack(alert, config).await,
            NotificationChannel::Email => self.send_email(alert, config).await,
            NotificationChannel::Webhook => self.send_webhook(alert, config).await,
        }
    }

    /// Send to console
    fn send_console(&self, alert: &Alert) -> Result<NotificationResult> {
        println!(
            "[ALERT] {} - {} - {} - {}",
            alert.timestamp(),
            alert.severity(),
            alert.alert_type(),
            alert.message()
        );

        Ok(NotificationResult::Success("sent to console".to_string()))
    }

    /// Send to Slack via incoming webhook
    async fn send_slack(
        &self,
        alert: &Alert,
        config: &NotificationConfig,
    ) -> Result<NotificationResult> {
        if let Some(webhook_url) = config.slack_webhook() {
            let payload = build_slack_message(alert, config);
            log::debug!("Sending Slack notification to webhook");
            log::trace!("Slack payload: {}", payload);

            let client = reqwest::Client::new();
            match client
                .post(webhook_url)
                .header("Content-Type", "application/json")
                .body(payload)
                .send()
                .await
            {
                Ok(resp) => {
                    if resp.status().is_success() {
                        log::info!("Slack notification sent successfully");
                        Ok(NotificationResult::Success("sent to Slack".to_string()))
                    } else {
                        let status = resp.status();
                        let body = resp.text().await.unwrap_or_default();
                        log::warn!("Slack API returned {}: {}", status, body);
                        Ok(NotificationResult::Failure(format!(
                            "Slack returned {}: {}",
                            status, body
                        )))
                    }
                }
                Err(e) => {
                    log::warn!("Failed to send Slack notification: {}", e);
                    Ok(NotificationResult::Failure(format!(
                        "Slack request failed: {}",
                        e
                    )))
                }
            }
        } else {
            log::debug!("Slack webhook not configured, skipping");
            Ok(NotificationResult::Failure(
                "Slack webhook not configured".to_string(),
            ))
        }
    }

    /// Send via email
    async fn send_email(
        &self,
        alert: &Alert,
        config: &NotificationConfig,
    ) -> Result<NotificationResult> {
        match (
            config.smtp_host(),
            config.smtp_port(),
            config.smtp_user(),
            config.smtp_password(),
        ) {
            (Some(host), Some(port), Some(user), Some(password))
                if !config.email_recipients().is_empty() =>
            {
                let from: Mailbox = user
                    .parse()
                    .with_context(|| format!("invalid SMTP sender address: {user}"))?;
                let recipients = config
                    .email_recipients()
                    .iter()
                    .map(|recipient| {
                        recipient
                            .parse::<Mailbox>()
                            .with_context(|| format!("invalid SMTP recipient address: {recipient}"))
                    })
                    .collect::<Result<Vec<_>>>()?;

                let subject = if let Some(label) = config.notification_label() {
                    format!(
                        "[Stackdog][{}][{}] {}",
                        label,
                        alert.severity(),
                        alert.alert_type()
                    )
                } else {
                    format!("[Stackdog][{}] {}", alert.severity(), alert.alert_type())
                };
                let mut message_builder = Message::builder().from(from).subject(subject);

                for recipient in recipients {
                    message_builder = message_builder.to(recipient);
                }

                let message = message_builder.multipart(
                    MultiPart::alternative()
                        .singlepart(SinglePart::plain(build_email_text(alert, config)))
                        .singlepart(SinglePart::html(build_email_html(alert, config))),
                )?;

                let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(host)?
                    .port(port)
                    .credentials(Credentials::new(user.to_string(), password.to_string()))
                    .build();

                match mailer.send(message).await {
                    Ok(_) => Ok(NotificationResult::Success("sent to email".to_string())),
                    Err(err) => Ok(NotificationResult::Failure(format!(
                        "SMTP delivery failed: {}",
                        err
                    ))),
                }
            }
            _ => Ok(NotificationResult::Failure(
                "SMTP not configured".to_string(),
            )),
        }
    }

    /// Send to webhook
    async fn send_webhook(
        &self,
        alert: &Alert,
        config: &NotificationConfig,
    ) -> Result<NotificationResult> {
        if let Some(webhook_url) = config.webhook_url() {
            let payload = build_webhook_payload(alert, config);
            let client = reqwest::Client::new();
            match client
                .post(webhook_url)
                .header("Content-Type", "application/json")
                .body(payload)
                .send()
                .await
            {
                Ok(resp) => {
                    if resp.status().is_success() {
                        Ok(NotificationResult::Success("sent to webhook".to_string()))
                    } else {
                        let status = resp.status();
                        let body = resp.text().await.unwrap_or_default();
                        Ok(NotificationResult::Failure(format!(
                            "Webhook returned {}: {}",
                            status, body
                        )))
                    }
                }
                Err(err) => Ok(NotificationResult::Failure(format!(
                    "Webhook request failed: {}",
                    err
                ))),
            }
        } else {
            Ok(NotificationResult::Failure(
                "Webhook URL not configured".to_string(),
            ))
        }
    }
}

pub async fn dispatch_stored_alert(
    alert: &crate::database::models::Alert,
    config: &NotificationConfig,
) -> Result<usize> {
    let mut runtime_alert = Alert::new(alert.alert_type, alert.severity, alert.message.clone());

    if let Some(metadata) = &alert.metadata {
        if let Some(container_id) = &metadata.container_id {
            runtime_alert.add_metadata("container_id".into(), container_id.clone());
        }
        if let Some(source) = &metadata.source {
            runtime_alert.add_metadata("source".into(), source.clone());
        }
        if let Some(reason) = &metadata.reason {
            runtime_alert.add_metadata("reason".into(), reason.clone());
        }
        for (key, value) in &metadata.extra {
            runtime_alert.add_metadata(key.clone(), value.clone());
        }
    }

    let channels = config.configured_channels_for_stored_alert(alert);
    let mut sent = 0;
    for channel in &channels {
        match channel.send(&runtime_alert, config).await? {
            NotificationResult::Success(_) => sent += 1,
            NotificationResult::Failure(message) => {
                log::warn!("Action notification channel reported failure: {}", message)
            }
        }
    }

    Ok(sent)
}

/// Notification result
#[derive(Debug, Clone)]
pub enum NotificationResult {
    Success(String),
    Failure(String),
}

impl std::fmt::Display for NotificationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NotificationResult::Success(msg) => write!(f, "Success: {}", msg),
            NotificationResult::Failure(msg) => write!(f, "Failure: {}", msg),
        }
    }
}

/// Route alerts by severity
pub fn route_by_severity(severity: AlertSeverity) -> Vec<NotificationChannel> {
    match severity {
        AlertSeverity::Critical => {
            // Critical goes to all channels
            vec![
                NotificationChannel::Console,
                NotificationChannel::Slack,
                NotificationChannel::Email,
                NotificationChannel::Webhook,
            ]
        }
        AlertSeverity::High => {
            vec![
                NotificationChannel::Console,
                NotificationChannel::Slack,
                NotificationChannel::Webhook,
            ]
        }
        AlertSeverity::Medium => {
            vec![NotificationChannel::Console, NotificationChannel::Slack]
        }
        AlertSeverity::Low => {
            vec![NotificationChannel::Console]
        }
        AlertSeverity::Info => {
            vec![NotificationChannel::Console]
        }
    }
}

/// Convert severity to Slack color
pub fn severity_to_slack_color(severity: AlertSeverity) -> &'static str {
    match severity {
        AlertSeverity::Critical => "#FF0000",
        AlertSeverity::High => "#FF8C00",
        AlertSeverity::Medium => "#FFD700",
        AlertSeverity::Low => "#008000",
        AlertSeverity::Info => "#0000FF",
    }
}

/// Build Slack message payload
pub fn build_slack_message(alert: &Alert, config: &NotificationConfig) -> String {
    let mut fields = vec![
        serde_json::json!({"title": "Severity", "value": alert.severity().to_string(), "short": true}),
        serde_json::json!({"title": "Status", "value": alert.status().to_string(), "short": true}),
        serde_json::json!({"title": "Time", "value": alert.timestamp().to_rfc3339(), "short": true}),
    ];
    if let Some(label) = config.notification_label() {
        fields.push(serde_json::json!({"title": "Instance", "value": label, "short": true}));
    }

    serde_json::json!({
        "text": "🐕 Stackdog Security Alert",
        "attachments": [{
            "color": severity_to_slack_color(alert.severity()),
            "title": format!("{:?}", alert.alert_type()),
            "text": alert.message(),
            "fields": fields
        }]
    })
    .to_string()
}

/// Build webhook payload
pub fn build_webhook_payload(alert: &Alert, config: &NotificationConfig) -> String {
    serde_json::json!({
        "alert_type": alert.alert_type().to_string(),
        "severity": alert.severity().to_string(),
        "message": alert.message(),
        "timestamp": alert.timestamp().to_rfc3339(),
        "status": alert.status().to_string(),
        "metadata": alert.metadata(),
        "instance_label": config.notification_label(),
    })
    .to_string()
}

fn build_email_text(alert: &Alert, config: &NotificationConfig) -> String {
    format!(
        "Stackdog Security Alert\n{}\nType: {}\nSeverity: {}\nStatus: {}\nTime: {}\n\n{}\n",
        config
            .notification_label()
            .map(|label| format!("Instance: {label}\n"))
            .unwrap_or_default(),
        alert.alert_type(),
        alert.severity(),
        alert.status(),
        alert.timestamp().to_rfc3339(),
        alert.message(),
    )
}

fn build_email_html(alert: &Alert, config: &NotificationConfig) -> String {
    format!(
        "<h2>Stackdog Security Alert</h2>{}<p><strong>Type:</strong> {}</p><p><strong>Severity:</strong> {}</p><p><strong>Status:</strong> {}</p><p><strong>Time:</strong> {}</p><p>{}</p>",
        config
            .notification_label()
            .map(|label| format!("<p><strong>Instance:</strong> {label}</p>"))
            .unwrap_or_default(),
        alert.alert_type(),
        alert.severity(),
        alert.status(),
        alert.timestamp().to_rfc3339(),
        alert.message(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    fn clear_notification_env() {
        env::remove_var("STACKDOG_SLACK_WEBHOOK_URL");
        env::remove_var("STACKDOG_WEBHOOK_URL");
        env::remove_var("STACKDOG_SMTP_HOST");
        env::remove_var("STACKDOG_SMTP_PORT");
        env::remove_var("STACKDOG_SMTP_USER");
        env::remove_var("STACKDOG_SMTP_PASSWORD");
        env::remove_var("STACKDOG_EMAIL_RECIPIENTS");
        env::remove_var("STACKDOG_NOTIFICATION_LABEL");
        env::remove_var("STACKDOG_NOTIFICATION_MIN_SEVERITY");
        env::remove_var("STACKDOG_NOTIFY_IP_BAN_ACTIONS");
        env::remove_var("STACKDOG_NOTIFY_QUARANTINE_ACTIONS");
    }

    #[tokio::test]
    async fn test_console_notification() {
        let channel = NotificationChannel::Console;
        let alert = Alert::new(
            crate::alerting::alert::AlertType::ThreatDetected,
            AlertSeverity::High,
            "Test".to_string(),
        );

        let result = channel.send(&alert, &NotificationConfig::default()).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_notification_config_from_env_reads_channels() {
        let _guard = ENV_MUTEX.lock().unwrap();
        clear_notification_env();

        env::set_var(
            "STACKDOG_SLACK_WEBHOOK_URL",
            "https://hooks.slack.test/services/1",
        );
        env::set_var("STACKDOG_WEBHOOK_URL", "https://example.test/webhook");
        env::set_var("STACKDOG_SMTP_HOST", "smtp.example.com");
        env::set_var("STACKDOG_SMTP_PORT", "2525");
        env::set_var("STACKDOG_SMTP_USER", "alerts@example.com");
        env::set_var("STACKDOG_SMTP_PASSWORD", "secret");
        env::set_var(
            "STACKDOG_EMAIL_RECIPIENTS",
            "soc@example.com,oncall@example.com",
        );
        env::set_var("STACKDOG_NOTIFICATION_LABEL", "prod-eu-1");

        let config = NotificationConfig::from_env();

        assert_eq!(
            config.slack_webhook(),
            Some("https://hooks.slack.test/services/1")
        );
        assert_eq!(config.webhook_url(), Some("https://example.test/webhook"));
        assert_eq!(config.smtp_host(), Some("smtp.example.com"));
        assert_eq!(config.smtp_port(), Some(2525));
        assert_eq!(config.smtp_user(), Some("alerts@example.com"));
        assert_eq!(config.smtp_password(), Some("secret"));
        assert_eq!(
            config.email_recipients(),
            &[
                "soc@example.com".to_string(),
                "oncall@example.com".to_string()
            ]
        );
        assert_eq!(config.notification_label(), Some("prod-eu-1"));
        assert_eq!(config.minimum_severity(), AlertSeverity::Info);

        clear_notification_env();
    }

    #[test]
    fn test_notification_config_from_env_reads_minimum_severity() {
        let _guard = ENV_MUTEX.lock().unwrap();
        clear_notification_env();
        env::set_var("STACKDOG_NOTIFICATION_MIN_SEVERITY", "critical");

        let config = NotificationConfig::from_env();
        assert_eq!(config.minimum_severity(), AlertSeverity::Critical);

        clear_notification_env();
    }

    #[test]
    fn test_env_flag_enabled_honors_boolean_values() {
        let _guard = ENV_MUTEX.lock().unwrap();
        clear_notification_env();

        assert!(env_flag_enabled("STACKDOG_NOTIFY_IP_BAN_ACTIONS", true));
        env::set_var("STACKDOG_NOTIFY_IP_BAN_ACTIONS", "false");
        assert!(!env_flag_enabled("STACKDOG_NOTIFY_IP_BAN_ACTIONS", true));
        env::set_var("STACKDOG_NOTIFY_IP_BAN_ACTIONS", "yes");
        assert!(env_flag_enabled("STACKDOG_NOTIFY_IP_BAN_ACTIONS", false));

        clear_notification_env();
    }

    #[test]
    fn test_severity_to_slack_color() {
        assert_eq!(severity_to_slack_color(AlertSeverity::Critical), "#FF0000");
        assert_eq!(severity_to_slack_color(AlertSeverity::High), "#FF8C00");
    }

    #[test]
    fn test_route_by_severity() {
        let critical_routes = route_by_severity(AlertSeverity::Critical);
        assert!(critical_routes.len() >= 3);

        let info_routes = route_by_severity(AlertSeverity::Info);
        assert_eq!(info_routes.len(), 1);
    }

    #[test]
    fn test_configured_channels_for_stored_alert_filters_non_action_below_threshold() {
        let config = NotificationConfig::default()
            .with_slack_webhook("https://hooks.slack.test/services/1".into())
            .with_minimum_severity(AlertSeverity::Critical);
        let alert = crate::database::models::Alert::new(
            crate::alerting::alert::AlertType::ThreatDetected,
            AlertSeverity::High,
            "High severity finding".to_string(),
        );

        let channels = config.configured_channels_for_stored_alert(&alert);
        assert!(channels.is_empty());
    }

    #[test]
    fn test_configured_channels_for_stored_alert_keeps_action_notifications() {
        let config = NotificationConfig::default()
            .with_slack_webhook("https://hooks.slack.test/services/1".into())
            .with_minimum_severity(AlertSeverity::Critical);
        let alert = crate::database::models::Alert::new(
            crate::alerting::alert::AlertType::SystemEvent,
            AlertSeverity::Info,
            "Released IP ban".to_string(),
        )
        .with_metadata(crate::database::models::AlertMetadata::default().with_source("ip_ban"));

        let channels = config.configured_channels_for_stored_alert(&alert);
        assert!(channels.contains(&NotificationChannel::Console));
        assert!(channels.contains(&NotificationChannel::Slack));
    }

    #[test]
    fn test_build_webhook_payload_is_valid_json() {
        let alert = Alert::new(
            crate::alerting::alert::AlertType::ThreatDetected,
            AlertSeverity::High,
            "Webhook test".to_string(),
        );

        let payload = build_webhook_payload(
            &alert,
            &NotificationConfig::default().with_notification_label("prod-eu-1".into()),
        );
        let json: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(json["severity"], "High");
        assert_eq!(json["message"], "Webhook test");
        assert_eq!(json["instance_label"], "prod-eu-1");
    }

    #[test]
    fn test_build_slack_message_includes_instance_label() {
        let alert = Alert::new(
            crate::alerting::alert::AlertType::ThreatDetected,
            AlertSeverity::High,
            "Slack test".to_string(),
        );

        let payload = build_slack_message(
            &alert,
            &NotificationConfig::default().with_notification_label("prod-eu-1".into()),
        );
        let json: serde_json::Value = serde_json::from_str(&payload).unwrap();
        let fields = json["attachments"][0]["fields"].as_array().unwrap();
        assert!(fields
            .iter()
            .any(|field| { field["title"] == "Instance" && field["value"] == "prod-eu-1" }));
    }

    #[tokio::test]
    async fn test_email_channel_requires_recipients() {
        let channel = NotificationChannel::Email;
        let alert = Alert::new(
            crate::alerting::alert::AlertType::ThreatDetected,
            AlertSeverity::High,
            "Email test".to_string(),
        );

        let result = channel
            .send(
                &alert,
                &NotificationConfig::default()
                    .with_smtp_host("smtp.example.com".to_string())
                    .with_smtp_port(587),
            )
            .await
            .unwrap();

        assert!(matches!(result, NotificationResult::Failure(_)));
    }

    #[test]
    fn test_configured_channels_excludes_unconfigured_targets() {
        let config = NotificationConfig::default().with_webhook_url("https://example.test".into());
        let channels = config.configured_channels_for_severity(AlertSeverity::Critical);

        assert!(channels.contains(&NotificationChannel::Console));
        assert!(channels.contains(&NotificationChannel::Webhook));
        assert!(!channels.contains(&NotificationChannel::Slack));
        assert!(!channels.contains(&NotificationChannel::Email));
    }

    #[test]
    fn test_configured_channels_include_email_when_fully_configured() {
        let config = NotificationConfig::default()
            .with_smtp_host("smtp.example.com".into())
            .with_smtp_port(587)
            .with_smtp_user("alerts@example.com".into())
            .with_smtp_password("secret".into())
            .with_email_recipients(vec!["security@example.com".into()]);
        let channels = config.configured_channels_for_severity(AlertSeverity::Critical);

        assert!(channels.contains(&NotificationChannel::Email));
    }
}
