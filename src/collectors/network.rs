//! Network traffic collector
//!
//! Captures network traffic for security analysis

use anyhow::Result;
use chrono::Utc;
use std::collections::HashMap;

use crate::docker::{ContainerInfo, DockerClient};
use crate::events::security::NetworkEvent;

/// Network traffic collector
pub struct NetworkCollector {
    client: DockerClient,
    previous: HashMap<String, (u64, u64)>,
}

impl NetworkCollector {
    pub async fn new() -> Result<Self> {
        Ok(Self {
            client: DockerClient::new().await?,
            previous: HashMap::new(),
        })
    }

    pub async fn collect_outbound_events(&mut self) -> Result<Vec<NetworkEvent>> {
        let containers = self.client.list_containers(false).await?;
        let mut events = Vec::new();

        for container in containers {
            if container.status != "Running" {
                continue;
            }

            let stats = self.client.get_container_stats(&container.id).await?;
            let current = (stats.network_tx, stats.network_tx_packets);
            let previous = self.previous.insert(container.id.clone(), current);

            if let Some((prev_tx_bytes, prev_tx_packets)) = previous {
                let delta_bytes = current.0.saturating_sub(prev_tx_bytes);
                let delta_packets = current.1.saturating_sub(prev_tx_packets);
                if delta_bytes == 0 && delta_packets == 0 {
                    continue;
                }

                if let Some(event) = build_network_event(&container, delta_bytes, delta_packets) {
                    events.push(event);
                }
            }
        }

        Ok(events)
    }
}

impl Default for NetworkCollector {
    fn default() -> Self {
        panic!("Use NetworkCollector::new().await")
    }
}

fn build_network_event(
    container: &ContainerInfo,
    _delta_tx_bytes: u64,
    _delta_tx_packets: u64,
) -> Option<NetworkEvent> {
    let src_ip = container
        .network_settings
        .values()
        .find(|ip| !ip.is_empty())
        .cloned()?;

    Some(NetworkEvent {
        src_ip,
        dst_ip: "0.0.0.0".to_string(),
        src_port: 0,
        dst_port: 0,
        protocol: "tcp".to_string(),
        timestamp: Utc::now(),
        container_id: Some(container.id.clone()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_network_event_uses_container_ip() {
        let container = ContainerInfo {
            id: "abc123".to_string(),
            name: "wordpress".to_string(),
            image: "wordpress:latest".to_string(),
            status: "Running".to_string(),
            created: String::new(),
            network_settings: HashMap::from([("bridge".to_string(), "172.17.0.5".to_string())]),
            labels: HashMap::new(),
        };

        let event = build_network_event(&container, 64_000, 250).unwrap();
        assert_eq!(event.src_ip, "172.17.0.5");
        assert_eq!(event.container_id.as_deref(), Some("abc123"));
        assert_eq!(event.dst_port, 0);
    }

    #[test]
    fn test_build_network_event_requires_ip() {
        let container = ContainerInfo {
            id: "abc123".to_string(),
            name: "wordpress".to_string(),
            image: "wordpress:latest".to_string(),
            status: "Running".to_string(),
            created: String::new(),
            network_settings: HashMap::new(),
            labels: HashMap::new(),
        };

        assert!(build_network_event(&container, 64_000, 250).is_none());
    }
}
