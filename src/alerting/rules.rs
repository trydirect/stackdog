//! Alert rules

use anyhow::Result;

use crate::alerting::alert::AlertSeverity;
use crate::alerting::notifications::{route_by_severity, NotificationChannel};

/// Alert rule
#[derive(Debug, Clone)]
pub struct AlertRule {
    minimum_severity: AlertSeverity,
    channels: Vec<NotificationChannel>,
}

impl AlertRule {
    pub fn new() -> Result<Self> {
        Ok(Self {
            minimum_severity: AlertSeverity::Low,
            channels: route_by_severity(AlertSeverity::High),
        })
    }

    pub fn with_minimum_severity(mut self, severity: AlertSeverity) -> Self {
        self.minimum_severity = severity;
        self
    }

    pub fn with_channels(mut self, channels: Vec<NotificationChannel>) -> Self {
        self.channels = channels;
        self
    }

    pub fn matches(&self, severity: AlertSeverity) -> bool {
        severity >= self.minimum_severity
    }

    pub fn channels_for(&self, severity: AlertSeverity) -> Vec<NotificationChannel> {
        if self.matches(severity) {
            if self.channels.is_empty() {
                route_by_severity(severity)
            } else {
                self.channels.clone()
            }
        } else {
            Vec::new()
        }
    }
}

impl Default for AlertRule {
    fn default() -> Self {
        Self::new().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alert_rule_matches_minimum_severity() {
        let rule = AlertRule::default().with_minimum_severity(AlertSeverity::Medium);
        assert!(rule.matches(AlertSeverity::High));
        assert!(!rule.matches(AlertSeverity::Low));
    }

    #[test]
    fn test_alert_rule_uses_custom_channels() {
        let rule = AlertRule::default()
            .with_minimum_severity(AlertSeverity::Low)
            .with_channels(vec![NotificationChannel::Webhook]);

        let channels = rule.channels_for(AlertSeverity::Critical);
        assert_eq!(channels.len(), 1);
        assert!(matches!(channels[0], NotificationChannel::Webhook));
    }
}
