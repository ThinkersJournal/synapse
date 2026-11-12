// SPDX-License-Identifier: MIT OR Apache-2.0
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::sync::{Mutex, RwLock};
use tracing::info;

#[cfg(feature = "mdns")]
use auto_discovery::{DiscoveryConfig, ProtocolType, ServiceDiscovery, ServiceInfo, ServiceType};

use crate::error::{Result, SynapseError};
use crate::transport::abstraction::{
    ConnectivityResult, DeliveryReceipt, MessageUrgency, RawInbox, Transport,
    TransportCapabilities, TransportEstimate, TransportMetrics, TransportReceive, TransportStatus,
    TransportTarget, TransportType, UnmeasuredMetric,
};
use crate::types::SecureMessage;

/// Discovered service information
#[derive(Debug, Clone)]
pub struct DiscoveredService {
    pub name: String,
    pub service_type: String,
    pub host: String,
    pub port: u16,
    pub addresses: Vec<IpAddr>,
    pub txt_records: HashMap<String, String>,
    pub last_seen: Instant,
}

impl DiscoveredService {
    pub fn socket_addrs(&self) -> Vec<SocketAddr> {
        self.addresses
            .iter()
            .map(|addr| SocketAddr::new(*addr, self.port))
            .collect()
    }
}

/// How many scan intervals a discovered service may go unseen before it is treated as gone.
const EXPIRY_SCAN_INTERVALS: u32 = 3;

/// Configuration for auto-discovery transport
#[derive(Debug, Clone)]
pub struct SynapseDiscoveryConfig {
    pub identifier: String,
    pub service_type: String,
    pub port: u16,
    pub scan_interval: Duration,
    pub protocols: Vec<String>,
}

impl SynapseDiscoveryConfig {
    pub fn new(identifier: String, port: u16) -> Self {
        Self {
            identifier,
            service_type: "_synapse._tcp".to_string(),
            port,
            scan_interval: Duration::from_secs(60),
            protocols: vec!["mdns".to_string()],
        }
    }

    pub fn with_service_type(mut self, service_type: String) -> Self {
        self.service_type = service_type;
        self
    }

    pub fn with_scan_interval(mut self, interval: Duration) -> Self {
        self.scan_interval = interval;
        self
    }

    pub fn with_protocols(mut self, protocols: Vec<String>) -> Self {
        self.protocols = protocols;
        self
    }

    /// How long a discovered service stays reachable without being seen again.
    pub fn expiry(&self) -> Duration {
        self.scan_interval.saturating_mul(EXPIRY_SCAN_INTERVALS)
    }
}

/// Auto-discovery based transport implementation
pub struct DiscoveryTransport {
    config: SynapseDiscoveryConfig,
    #[cfg(feature = "mdns")]
    discovery: Arc<Mutex<Option<ServiceDiscovery>>>,
    discovered_services: Arc<RwLock<HashMap<String, DiscoveredService>>>,
    metrics: Arc<RwLock<TransportMetrics>>,
    running: Arc<RwLock<bool>>,
}

impl DiscoveryTransport {
    pub async fn new(config: SynapseDiscoveryConfig) -> Result<Self> {
        info!(
            "Creating DiscoveryTransport with service type: {}",
            config.service_type
        );

        let transport = Self {
            config,
            #[cfg(feature = "mdns")]
            discovery: Arc::new(Mutex::new(None)),
            discovered_services: Arc::new(RwLock::new(HashMap::new())),
            // Discovery carries no messages, so it never reports a send reliability.
            metrics: Arc::new(RwLock::new(TransportMetrics {
                transport_type: TransportType::AutoDiscovery,
                reliability_score: 0.0,
                ..TransportMetrics::default()
            })),
            running: Arc::new(RwLock::new(false)),
        };

        Ok(transport)
    }

    #[cfg(feature = "mdns")]
    async fn initialize_discovery(&self) -> Result<()> {
        let service_type = ServiceType::new(&self.config.service_type)
            .map_err(|e| SynapseError::TransportError(format!("Invalid service type: {}", e)))?;

        let discovery_config = DiscoveryConfig::new()
            .with_service_type(service_type)
            .with_protocol(ProtocolType::Mdns)
            .with_timeout(self.config.scan_interval);

        let discovery = ServiceDiscovery::new(discovery_config).await.map_err(|e| {
            SynapseError::TransportError(format!("Failed to create discovery: {}", e))
        })?;

        // Register our own service
        let service_info = ServiceInfo::new(
            &self.config.identifier,
            &self.config.service_type,
            self.config.port,
            Some(vec![
                ("synapse", "true"),
                (
                    "synapse_protocol",
                    &crate::types::PROTOCOL_VERSION.to_string(),
                ),
                ("protocols", &self.config.protocols.join(",")),
            ]),
        )
        .map_err(|e| {
            SynapseError::TransportError(format!("Failed to create service info: {}", e))
        })?;

        discovery
            .register_service(service_info)
            .await
            .map_err(|e| {
                SynapseError::TransportError(format!("Failed to register service: {}", e))
            })?;

        info!(
            "Registered service: {} on port {}",
            self.config.identifier, self.config.port
        );

        *self.discovery.lock().await = Some(discovery);
        Ok(())
    }

    #[cfg(not(feature = "mdns"))]
    async fn initialize_discovery(&self) -> Result<()> {
        tracing::warn!("mDNS discovery not available - compiled without mdns feature");
        Ok(())
    }

    /// Whether `service` was seen recently enough to still count as present.
    fn is_fresh(&self, service: &DiscoveredService) -> bool {
        service.last_seen.elapsed() <= self.config.expiry()
    }

    pub async fn get_discovered_services(&self) -> HashMap<String, DiscoveredService> {
        self.discovered_services
            .read()
            .await
            .iter()
            .filter(|(_, service)| self.is_fresh(service))
            .map(|(name, service)| (name.clone(), service.clone()))
            .collect()
    }

    pub async fn find_service_by_name(&self, name: &str) -> Option<DiscoveredService> {
        self.discovered_services
            .read()
            .await
            .get(name)
            .filter(|service| self.is_fresh(service))
            .cloned()
    }

    pub async fn find_services_by_type(&self, service_type: &str) -> Vec<DiscoveredService> {
        self.discovered_services
            .read()
            .await
            .values()
            .filter(|service| service.service_type == service_type && self.is_fresh(service))
            .cloned()
            .collect()
    }
}

#[async_trait]
impl Transport for DiscoveryTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::AutoDiscovery
    }

    fn capabilities(&self) -> TransportCapabilities {
        // Discovery only: it finds services for other transports and carries no messages, so it
        // advertises no message capability at all.
        TransportCapabilities {
            reliable: false,
            real_time: false,
            broadcast: false,
            bidirectional: false,
            encrypted: false,
            network_spanning: false,
            max_message_size: 0,
            features: vec!["discovery_only".to_string()],
            supported_urgencies: Vec::<MessageUrgency>::new(),
            // `reliability_score`'s `0.0` is a fixed constant (this transport carries no
            // messages, so it always reports total unreliability), not an observation -- and
            // `0.0` is itself a meaningful reading, so leaving it off `unmeasured_metrics` would
            // let a caller mistake "deliberately constant" for "measured, and failing".
            // `average_latency_ms` is never set past its zero default either.
            unmeasured_metrics: vec![
                UnmeasuredMetric::AverageLatency,
                UnmeasuredMetric::ReliabilityScore,
            ],
        }
    }

    async fn can_reach(&self, target: &TransportTarget) -> bool {
        // Check if we have discovered a service that matches the target
        let services = self.discovered_services.read().await;

        // Look for exact match by identifier
        if services
            .get(&target.identifier)
            .is_some_and(|service| self.is_fresh(service))
        {
            return true;
        }

        // Look for services with matching capabilities
        for service in services.values().filter(|s| self.is_fresh(s)) {
            if target.required_capabilities.iter().all(|cap| {
                service.txt_records.contains_key(cap)
                    || service
                        .txt_records
                        .get("protocols")
                        .is_some_and(|p| p.contains(cap))
            }) {
                return true;
            }
        }

        false
    }

    async fn estimate_metrics(&self, _target: &TransportTarget) -> Result<TransportEstimate> {
        // `send_message` refuses (discovery carries no messages), so no target is available
        // through this transport, however recently its service was seen.
        Ok(TransportEstimate {
            latency: Duration::from_millis(1000),
            bandwidth: 0,
            reliability: 0.0,
            cost: 1.0,
            available: false,
            confidence: 1.0,
        })
    }

    async fn start(&self) -> Result<()> {
        info!("Starting DiscoveryTransport");

        *self.running.write().await = true;

        // Initialize mDNS discovery
        self.initialize_discovery().await?;

        // Start discovery loop - create a weak reference to avoid lifetime issues
        let discovered_services = self.discovered_services.clone();
        let discovery = self.discovery.clone();
        let running = self.running.clone();
        let scan_interval = self.config.scan_interval;
        let expiry = self.config.expiry();

        tokio::spawn(async move {
            while *running.read().await {
                // Drop services no scan has seen for a few intervals: a departed peer, or one
                // whose address another host now holds, must not stay reachable.
                discovered_services
                    .write()
                    .await
                    .retain(|_, service| service.last_seen.elapsed() <= expiry);

                #[cfg(feature = "mdns")]
                {
                    if let Some(disco) = discovery.lock().await.as_ref()
                        && let Ok(services) =
                            disco.discover_services(Some(ProtocolType::Mdns)).await
                    {
                        let mut discovered = discovered_services.write().await;
                        let now = Instant::now();

                        for service in services {
                            let discovered_service = DiscoveredService {
                                name: service.name().to_string(),
                                service_type: service.service_type().to_string(),
                                host: service.address().to_string(),
                                port: service.port(),
                                addresses: vec![service.address()],
                                txt_records: HashMap::new(),
                                last_seen: now,
                            };

                            discovered.insert(discovered_service.name.clone(), discovered_service);
                        }
                    }
                }

                tokio::time::sleep(scan_interval).await;
            }
        });

        info!("DiscoveryTransport started successfully");
        Ok(())
    }
    async fn stop(&self) -> Result<()> {
        info!("Stopping DiscoveryTransport");

        *self.running.write().await = false;

        #[cfg(feature = "mdns")]
        {
            // Take ownership of the discovery service to drop it
            *self.discovery.lock().await = None;
        }

        info!("DiscoveryTransport stopped");
        Ok(())
    }
    async fn send_message(
        &self,
        target: &TransportTarget,
        _message: &SecureMessage,
    ) -> Result<DeliveryReceipt> {
        // Discovery finds services for other transports; it carries no messages. This used to
        // return `Sent` whenever any service had been discovered, with nothing written anywhere
        // (spec §4), so it refuses instead.
        Err(SynapseError::TransportError(format!(
            "auto-discovery carries discovery only, not messages; cannot send to {}",
            target.identifier
        )))
    }

    async fn test_connectivity(&self, target: &TransportTarget) -> Result<ConnectivityResult> {
        let services = self.discovered_services.read().await;

        // Find matching service
        let service = if let Some(service) = services
            .get(&target.identifier)
            .filter(|service| self.is_fresh(service))
        {
            Some(service)
        } else {
            services
                .values()
                .filter(|s| self.is_fresh(s))
                .find(|service| {
                    target
                        .required_capabilities
                        .iter()
                        .all(|cap| service.txt_records.contains_key(cap))
                })
        };

        // Discovery carries no messages, so it is never "connected" for sending. This used to
        // report `connected` for any service seen in the last minute, with a fixed 10 ms round
        // trip that nothing measured (spec §4). What it discovered stays in `details`.
        let cannot_send = format!(
            "auto-discovery carries discovery only, not messages; this transport cannot send to {}",
            target.identifier
        );
        if let Some(service) = service {
            let age = service.last_seen.elapsed();
            Ok(ConnectivityResult {
                connected: false,
                rtt: None,
                quality: 0.0,
                error: Some(cannot_send),
                details: {
                    let mut details = HashMap::new();
                    details.insert("service_name".to_string(), service.name.clone());
                    details.insert("host".to_string(), service.host.clone());
                    details.insert("port".to_string(), service.port.to_string());
                    details.insert("last_seen".to_string(), format!("{:?} ago", age));
                    details
                },
            })
        } else {
            Ok(ConnectivityResult {
                connected: false,
                rtt: None,
                quality: 0.0,
                error: Some(format!(
                    "{cannot_send}; no matching service discovered either"
                )),
                details: HashMap::new(),
            })
        }
    }

    async fn status(&self) -> TransportStatus {
        TransportStatus::Running
    }

    async fn metrics(&self) -> TransportMetrics {
        self.metrics.read().await.clone()
    }
}

#[async_trait]
impl TransportReceive for DiscoveryTransport {
    async fn receive_raw(&self, _inbox: &mut RawInbox) -> Result<()> {
        // Discovery transport doesn't receive messages directly
        // It provides service information for other transports to use
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_departed_service_stops_being_reachable() {
        let transport = DiscoveryTransport::new(
            SynapseDiscoveryConfig::new("probe".to_string(), 0)
                .with_scan_interval(Duration::from_secs(10)),
        )
        .await
        .unwrap();
        let service = |name: &str, age: Duration| DiscoveredService {
            name: name.to_string(),
            service_type: "_synapse._tcp".to_string(),
            host: "127.0.0.1".to_string(),
            port: 9,
            addresses: vec![IpAddr::from([127, 0, 0, 1])],
            txt_records: HashMap::new(),
            last_seen: Instant::now().checked_sub(age).unwrap(),
        };
        {
            let mut map = transport.discovered_services.write().await;
            map.insert("fresh".into(), service("fresh", Duration::ZERO));
            map.insert("gone".into(), service("gone", Duration::from_secs(31)));
        }
        // Control: a recently seen service is still reachable and findable.
        assert!(
            transport
                .can_reach(&TransportTarget::new("fresh".to_string()))
                .await
        );
        assert!(transport.find_service_by_name("fresh").await.is_some());
        // Unseen for more than three scan intervals: gone from every answer. (`fresh` is removed
        // first: a target with no required capabilities matches any live service.)
        assert!(transport.find_services_by_type("_synapse._tcp").await.len() == 1);
        transport.discovered_services.write().await.remove("fresh");
        let gone = TransportTarget::new("gone".to_string());
        assert!(!transport.can_reach(&gone).await);
        assert!(transport.find_service_by_name("gone").await.is_none());
        assert!(
            !transport
                .get_discovered_services()
                .await
                .contains_key("gone")
        );
        assert!(
            transport
                .find_services_by_type("_synapse._tcp")
                .await
                .is_empty()
        );
        let result = transport.test_connectivity(&gone).await.unwrap();
        assert!(result.details.is_empty(), "{:?}", result.details);
    }

    #[tokio::test]
    async fn send_refuses_even_when_a_service_has_been_discovered() {
        // `new` binds nothing; only `start` touches the network.
        let transport =
            DiscoveryTransport::new(SynapseDiscoveryConfig::new("probe".to_string(), 0))
                .await
                .unwrap();
        // Control: a discovered service is present, the condition under which the old code
        // returned `Sent` without writing anything.
        transport.discovered_services.write().await.insert(
            "peer".to_string(),
            DiscoveredService {
                name: "peer".to_string(),
                service_type: "_synapse._tcp".to_string(),
                host: "127.0.0.1".to_string(),
                port: 9,
                addresses: vec![IpAddr::from([127, 0, 0, 1])],
                txt_records: HashMap::new(),
                last_seen: Instant::now(),
            },
        );
        let target = TransportTarget::new("peer".to_string());
        assert!(
            transport.can_reach(&target).await,
            "control: the service is discovered"
        );
        let message = SecureMessage::new(
            "peer",
            "probe",
            b"hi".to_vec(),
            crate::types::SecurityLevel::Public,
        );
        let err = transport.send_message(&target, &message).await.unwrap_err();
        assert!(err.to_string().contains("discovery only"), "{err}");
        let estimate = transport.estimate_metrics(&target).await.unwrap();
        assert!(!estimate.available);
        assert_eq!(estimate.reliability, 0.0);
        // Nor does it claim a connection or a round trip it never measured.
        let connectivity = transport.test_connectivity(&target).await.unwrap();
        assert!(!connectivity.connected);
        assert_eq!(connectivity.rtt, None);
        let why = connectivity.error.expect("says why it is not connected");
        assert!(why.contains("cannot send"), "{why}");
        assert_eq!(
            connectivity.details.get("service_name").map(String::as_str),
            Some("peer")
        );
    }
}
