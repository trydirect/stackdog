//! Notification tests
//!
//! Tests for notification channel functionality

use stackdog::alerting::alert::{Alert, AlertSeverity, AlertType};
use stackdog::alerting::notifications::{NotificationChannel, NotificationConfig};

#[actix_rt::test]
async fn test_console_notification() {
    let channel = NotificationChannel::Console;

    let alert = Alert::new(
        AlertType::ThreatDetected,
        AlertSeverity::High,
        "Test alert".to_string(),
    );

    // Console notification should succeed (just prints to stdout)
    let result = channel.send(&alert, &NotificationConfig::default()).await;

    // Should succeed (may just log)
    assert!(result.is_ok());
}

#[test]
fn test_notification_config_builder() {
    let config = NotificationConfig::default()
        .with_slack_webhook("https://hooks.slack.com/test".to_string())
        .with_smtp_host("smtp.example.com".to_string())
        .with_smtp_port(587)
        .with_webhook_url("https://example.com/webhook".to_string());

    assert_eq!(config.slack_webhook(), Some("https://hooks.slack.com/test"));
    assert_eq!(config.smtp_host(), Some("smtp.example.com"));
    assert_eq!(config.smtp_port(), Some(587));
}

#[test]
fn test_slack_notification_format() {
    let alert = Alert::new(
        AlertType::ThreatDetected,
        AlertSeverity::Critical,
        "Critical threat detected".to_string(),
    );

    // Build Slack payload
    let payload = build_slack_payload(&alert);

    assert!(payload.contains("Critical"));
    assert!(payload.contains("ThreatDetected"));
    assert!(payload.contains("Critical threat detected"));
}

#[test]
fn test_webhook_notification_format() {
    let alert = Alert::new(
        AlertType::RuleViolation,
        AlertSeverity::Medium,
        "Rule violation".to_string(),
    );

    // Build webhook payload
    let payload = build_webhook_payload(&alert);

    assert!(payload.contains("RuleViolation"));
    assert!(payload.contains("Medium"));
}

#[test]
fn test_notification_routing_by_severity() {
    use stackdog::alerting::notifications::route_by_severity;

    // Critical should route to all channels
    let channels = route_by_severity(AlertSeverity::Critical);
    assert!(!channels.is_empty());

    // Info should route to fewer channels
    let info_channels = route_by_severity(AlertSeverity::Info);
    assert!(info_channels.len() <= channels.len());
}

#[test]
fn test_alert_severity_to_slack_color() {
    use stackdog::alerting::notifications::severity_to_slack_color;

    assert_eq!(severity_to_slack_color(AlertSeverity::Critical), "#FF0000");
    assert_eq!(severity_to_slack_color(AlertSeverity::High), "#FF8C00");
    assert_eq!(severity_to_slack_color(AlertSeverity::Medium), "#FFD700");
    assert_eq!(severity_to_slack_color(AlertSeverity::Low), "#008000");
    assert_eq!(severity_to_slack_color(AlertSeverity::Info), "#0000FF");
}

#[test]
fn test_discord_notification_format() {
    use stackdog::alerting::notifications::build_discord_message;

    let alert = Alert::new(
        AlertType::ThreatDetected,
        AlertSeverity::Critical,
        "Critical threat detected".to_string(),
    );
    let config = NotificationConfig::default()
        .with_discord_webhook("https://discord.com/api/webhooks/test".to_string());

    let payload = build_discord_message(&alert, &config);

    assert!(payload.contains("Stackdog Security Alert"));
    assert!(payload.contains("Critical threat detected"));
    assert!(payload.contains("ThreatDetected"));
    assert!(payload.contains("Severity: Critical"));
}

#[test]
fn test_discord_message_fits_the_content_limit() {
    use stackdog::alerting::notifications::build_discord_message;

    // Discord rejects content over 2000 characters.
    let alert = Alert::new(
        AlertType::AnomalyDetected,
        AlertSeverity::High,
        "A".repeat(5000),
    );
    let payload = build_discord_message(&alert, &NotificationConfig::default());
    let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
    assert!(parsed["content"].as_str().unwrap().chars().count() <= 2000);
}

#[test]
fn test_discord_channel_routed_only_when_configured() {
    let configured = NotificationConfig::default()
        .with_discord_webhook("https://discord.com/api/webhooks/test".to_string());
    assert!(configured
        .configured_channels_for_severity(AlertSeverity::Critical)
        .iter()
        .any(|channel| matches!(channel, NotificationChannel::Discord)));

    let bare = NotificationConfig::default();
    assert!(!bare
        .configured_channels_for_severity(AlertSeverity::Critical)
        .iter()
        .any(|channel| matches!(channel, NotificationChannel::Discord)));
}

#[test]
fn test_telegram_notification_format() {
    use stackdog::alerting::notifications::build_telegram_message;

    let alert = Alert::new(
        AlertType::ThreatDetected,
        AlertSeverity::Critical,
        "Critical threat detected".to_string(),
    );
    let config =
        NotificationConfig::default().with_telegram("123:abc".to_string(), "-100123".to_string());

    let payload = build_telegram_message(&alert, &config);
    let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();

    assert_eq!(parsed["chat_id"], "-100123");
    assert!(parsed["text"]
        .as_str()
        .unwrap()
        .contains("Critical threat detected"));
    assert!(parsed["text"]
        .as_str()
        .unwrap()
        .contains("Stackdog Security Alert"));
    assert!(parsed["text"]
        .as_str()
        .unwrap()
        .contains("Severity: Critical"));
}

#[test]
fn test_telegram_message_fits_the_content_limit() {
    use stackdog::alerting::notifications::build_telegram_message;

    // Telegram rejects messages over 4096 characters.
    let alert = Alert::new(
        AlertType::AnomalyDetected,
        AlertSeverity::High,
        "A".repeat(10000),
    );
    let config =
        NotificationConfig::default().with_telegram("123:abc".to_string(), "-100123".to_string());
    let payload = build_telegram_message(&alert, &config);
    let parsed: serde_json::Value = serde_json::from_str(&payload).unwrap();
    assert!(parsed["text"].as_str().unwrap().chars().count() <= 4096);
}

#[test]
fn test_telegram_channel_routed_only_when_configured() {
    let configured =
        NotificationConfig::default().with_telegram("123:abc".to_string(), "-100123".to_string());
    assert!(configured
        .configured_channels_for_severity(AlertSeverity::Critical)
        .iter()
        .any(|channel| matches!(channel, NotificationChannel::Telegram)));

    assert!(!NotificationConfig::default()
        .configured_channels_for_severity(AlertSeverity::Critical)
        .iter()
        .any(|channel| matches!(channel, NotificationChannel::Telegram)));
}

#[test]
fn test_notification_result_display() {
    use stackdog::alerting::notifications::NotificationResult;

    let success = NotificationResult::Success("sent".to_string());
    assert!(format!("{}", success).contains("Success") || format!("{}", success).contains("sent"));

    let failure = NotificationResult::Failure("error".to_string());
    assert!(format!("{}", failure).contains("Failure") || format!("{}", failure).contains("error"));
}

// Helper functions for testing
fn build_slack_payload(alert: &Alert) -> String {
    format!(
        r#"{{
            "text": "{}",
            "attachments": [{{
                "color": "{}",
                "fields": [
                    {{"title": "Type", "value": "{:?}"}},
                    {{"title": "Message", "value": "{}"}}
                ]
            }}]
        }}"#,
        alert.message(),
        severity_to_slack_color(alert.severity()),
        alert.alert_type(),
        alert.message()
    )
}

fn build_webhook_payload(alert: &Alert) -> String {
    format!(
        r#"{{
            "alert_type": "{:?} ",
            "severity": "{:?} ",
            "message": "{}",
            "timestamp": "{}"
        }}"#,
        alert.alert_type(),
        alert.severity(),
        alert.message(),
        alert.timestamp()
    )
}

fn severity_to_slack_color(severity: AlertSeverity) -> &'static str {
    match severity {
        AlertSeverity::Critical => "#FF0000",
        AlertSeverity::High => "#FF8C00",
        AlertSeverity::Medium => "#FFD700",
        AlertSeverity::Low => "#008000",
        AlertSeverity::Info => "#0000FF",
    }
}
