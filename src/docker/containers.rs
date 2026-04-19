//! Container management

use crate::alerting::alert::{AlertSeverity, AlertType};
use crate::alerting::notifications::{dispatch_stored_alert, env_flag_enabled, NotificationConfig};
use crate::database::models::{Alert, AlertMetadata};
use crate::database::{create_alert, get_container_alert_summary, DbPool};
use crate::docker::client::{ContainerInfo, DockerClient};
use anyhow::Result;

/// Container manager
pub struct ContainerManager {
    docker: DockerClient,
    pool: DbPool,
}

impl ContainerManager {
    /// Create a new container manager
    pub async fn new(pool: DbPool) -> Result<Self> {
        let docker = DockerClient::new().await?;
        Ok(Self { docker, pool })
    }

    /// List all containers
    pub async fn list_containers(&self) -> Result<Vec<ContainerInfo>> {
        self.docker.list_containers(true).await
    }

    /// Get container by ID
    pub async fn get_container(&self, container_id: &str) -> Result<ContainerInfo> {
        self.docker.get_container_info(container_id).await
    }

    /// Get live container stats
    pub async fn get_container_stats(
        &self,
        container_id: &str,
    ) -> Result<crate::docker::client::ContainerStats> {
        self.docker.get_container_stats(container_id).await
    }

    /// Quarantine a container
    pub async fn quarantine_container(&self, container_id: &str, reason: &str) -> Result<()> {
        // Disconnect from networks
        self.docker.quarantine_container(container_id).await?;

        // Create alert
        let alert = Alert::new(
            AlertType::QuarantineApplied,
            AlertSeverity::High,
            format!("Container {} quarantined: {}", container_id, reason),
        )
        .with_metadata(
            AlertMetadata::default()
                .with_container_id(container_id)
                .with_source("quarantine")
                .with_reason(reason),
        );

        let stored_alert = create_alert(&self.pool, alert).await?;
        self.notify_action_alert(&stored_alert, "container quarantine")
            .await;

        log::info!("Container {} quarantined: {}", container_id, reason);
        Ok(())
    }

    /// Release a container from quarantine
    pub async fn release_container(&self, container_id: &str) -> Result<()> {
        // Reconnect to default network
        self.docker
            .release_container(container_id, "bridge")
            .await?;

        let alert = Alert::new(
            AlertType::SystemEvent,
            AlertSeverity::Info,
            format!("Container {} released from quarantine", container_id),
        )
        .with_metadata(
            AlertMetadata::default()
                .with_container_id(container_id)
                .with_source("quarantine")
                .with_reason("Container released from quarantine"),
        );
        let stored_alert = create_alert(&self.pool, alert).await?;
        self.notify_action_alert(&stored_alert, "container quarantine release")
            .await;

        log::info!("Container {} released from quarantine", container_id);
        Ok(())
    }

    /// Get container security status
    pub async fn get_container_security_status(
        &self,
        container_id: &str,
    ) -> Result<ContainerSecurityStatus> {
        let _info = self.docker.get_container_info(container_id).await?;
        let summary = get_container_alert_summary(&self.pool, container_id)?;

        Ok(ContainerSecurityStatus {
            container_id: container_id.to_string(),
            risk_score: summary.risk_score(),
            threats: summary.active_threats,
            security_state: summary.security_state().to_string(),
        })
    }

    async fn notify_action_alert(&self, alert: &Alert, action_name: &str) {
        if !env_flag_enabled("STACKDOG_NOTIFY_QUARANTINE_ACTIONS", true) {
            return;
        }

        let config = NotificationConfig::from_env();
        if let Err(err) = dispatch_stored_alert(alert, &config).await {
            log::warn!("Failed to send {} notification: {}", action_name, err);
        }
    }
}

/// Container security status
#[derive(Debug, Clone)]
pub struct ContainerSecurityStatus {
    pub container_id: String,
    pub risk_score: u32,
    pub threats: u32,
    pub security_state: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::{create_pool, init_database};

    #[actix_rt::test]
    async fn test_container_manager_creation() {
        let pool = create_pool(":memory:").unwrap();
        init_database(&pool).unwrap();

        // This test requires Docker daemon
        let result = ContainerManager::new(pool).await;

        if result.is_ok() {
            let manager = result.unwrap();
            let containers = manager.list_containers().await;
            assert!(containers.is_ok());
        }
    }
}
