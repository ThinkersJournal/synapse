// SPDX-License-Identifier: MIT OR Apache-2.0
// Removed unexpected cfg feature condition
use chrono;
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
/// Multi-transport layer for EMRP
///
/// This module provides the core transport abstraction and implementations
/// for different communication methods: TCP/UDP, auto-discovery, NAT traversal, and email.
// Core abstraction layer
pub mod abstraction;
pub mod manager;
pub mod security;

// Dependency injection providers for testability
pub mod providers;

// Transport implementations
#[cfg(not(target_arch = "wasm32"))]
pub mod discovery; // New auto-discovery based implementation

// Unified transport implementations - primary implementations
#[cfg(not(target_arch = "wasm32"))]
pub mod udp_unified;

// Re-export key types
pub use abstraction::{TransportCapabilities, TransportType};
pub use discovery::DiscoveryTransport;
// pub use auto_discovery::config::DiscoveryConfig; // Only available with mdns/auto_discovery features

// Transport trait and abstraction
// pub mod abstraction; // Commented out to avoid duplicate
// pub mod manager; // Commented out to avoid duplicate

// Discovery system
// pub mod discovery; // Commented out to avoid duplicate

// Platform-specific transport modules (not available in WASM)
#[cfg(not(target_arch = "wasm32"))]
pub mod http_unified;
// Consolidated TCP implementation - using tcp_unified as primary
#[cfg(all(feature = "email", not(target_arch = "wasm32")))]
pub mod email_unified; // Real SMTP send / SynapseSmtpServer receive (Direct mode)
#[cfg(not(target_arch = "wasm32"))]
pub mod mdns_enhanced;
#[cfg(not(target_arch = "wasm32"))]
pub mod nat_traversal;
#[cfg(not(target_arch = "wasm32"))]
pub mod quic_tls;
#[cfg(not(target_arch = "wasm32"))]
pub mod quic_unified;
#[cfg(not(target_arch = "wasm32"))]
pub mod tcp_unified; // Primary TCP implementation
// Unified transport implementations
#[cfg(not(target_arch = "wasm32"))]
pub mod llm_discovery;
#[cfg(not(target_arch = "wasm32"))]
pub mod router;
#[cfg(not(target_arch = "wasm32"))]
pub mod websocket_unified; // Re-enable WebSocket unified implementation

use crate::error::Result;
use std::time::{Duration, Instant};

/// Available transport routes with performance characteristics
#[derive(Debug, Clone)]
pub enum TransportRoute {
    // Platform-specific transport routes (not available in WASM)
    #[cfg(not(target_arch = "wasm32"))]
    DirectTcp {
        address: String,
        port: u16,
        latency_ms: u32,
        established_at: Instant,
    },
    #[cfg(not(target_arch = "wasm32"))]
    DirectUdp {
        address: String,
        port: u16,
        latency_ms: u32,
        established_at: Instant,
    },
    #[cfg(not(target_arch = "wasm32"))]
    Udp {
        address: String,
        latency: Duration,
        reliability: f64,
    },
    #[cfg(not(target_arch = "wasm32"))]
    WebSocket {
        url: String,
        latency: Duration,
        reliability: f64,
    },
    #[cfg(not(target_arch = "wasm32"))]
    Quic {
        address: String,
        latency: Duration,
        reliability: f64,
        multiplexed: bool,
    },
    #[cfg(not(target_arch = "wasm32"))]
    LocalMdns {
        service_name: String,
        address: String,
        port: u16,
        latency_ms: u32,
        discovered_at: Instant,
    },
    #[cfg(not(target_arch = "wasm32"))]
    NatTraversal {
        method: NatMethod,
        external_address: String,
        external_port: u16,
        latency_ms: u32,
        established_at: Instant,
    },
    #[cfg(not(target_arch = "wasm32"))]
    FastEmailRelay {
        relay_server: String,
        estimated_latency_ms: u32,
    },
    #[cfg(not(target_arch = "wasm32"))]
    StandardEmail { estimated_latency_min: u32 },
    #[cfg(not(target_arch = "wasm32"))]
    EmailDiscovery {
        target_transport: Box<TransportRoute>,
    },

    // WASM-compatible transport routes
    #[cfg(target_arch = "wasm32")]
    WebSocket {
        url: String,
        latency_ms: u32,
        established_at: Instant,
    },
    #[cfg(target_arch = "wasm32")]
    WebRtc {
        peer_connection: String,
        latency_ms: u32,
        established_at: Instant,
    },
    #[cfg(target_arch = "wasm32")]
    WebAssembly { estimated_latency_ms: u32 },
}

/// NAT traversal methods (not available in WASM)
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NatMethod {
    Upnp,
    Stun { server: String },
    Turn { server: String, username: String },
    IceCandidate,
}

/// Connection offer for transport negotiation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionOffer {
    pub entity_id: String,
    // Platform-specific endpoints (not available in WASM)
    #[cfg(not(target_arch = "wasm32"))]
    pub tcp_endpoints: Vec<String>,
    #[cfg(not(target_arch = "wasm32"))]
    pub udp_endpoints: Vec<String>,
    #[cfg(not(target_arch = "wasm32"))]
    pub stun_servers: Vec<String>,
    #[cfg(not(target_arch = "wasm32"))]
    pub turn_servers: Vec<TurnServer>,

    // Common fields
    pub capabilities: Vec<String>,
    pub public_key: String,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub priority: u8, // 0-255, higher = more preferred

    // WASM-specific endpoints
    #[cfg(target_arch = "wasm32")]
    pub websocket_endpoints: Vec<String>,
    #[cfg(target_arch = "wasm32")]
    pub webrtc_endpoints: Vec<String>,
}

/// TURN server configuration (not available in WASM)
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TurnServer {
    pub url: String,
    pub username: String,
    pub credential: String,
}

/// Transport performance metrics
#[derive(Debug, Clone)]
pub struct TransportMetrics {
    pub latency: Duration,
    pub throughput_bps: u64,
    pub packet_loss: f32,
    pub jitter_ms: u32,
    pub reliability_score: f32, // 0.0-1.0
    pub last_updated: Instant,
}

impl Default for TransportMetrics {
    fn default() -> Self {
        Self {
            latency: Duration::from_millis(50),
            throughput_bps: 1_000_000, // 1 Mbps
            packet_loss: 0.0,
            jitter_ms: 10,
            reliability_score: 0.95,
            last_updated: Instant::now(),
        }
    }
}

/// Hybrid connection combining multiple transports
#[derive(Debug)]
pub struct HybridConnection {
    pub primary: TransportRoute,
    pub fallback: TransportRoute,
    pub discovery_latency: Duration,
    pub connection_latency: Duration,
    pub total_setup_time: Duration,
    pub metrics: TransportMetrics,
}

/// Transport discovery and testing utilities
pub struct TransportDiscovery {
    discovery_timeout: Duration,
    // ...existing code...
}

impl Default for TransportDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

impl TransportDiscovery {
    pub fn new() -> Self {
        Self {
            discovery_timeout: Duration::from_secs(10),
        }
    }

    /// Discover all available transports to a target (non-WASM platforms)
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn discover_transports(&mut self, target: &str) -> Result<Vec<TransportRoute>> {
        let mut routes = Vec::new();

        // Try direct TCP connection
        if let Ok(tcp_route) = self.test_direct_tcp(target).await {
            routes.push(tcp_route);
        }

        // Try direct UDP connection
        if let Ok(udp_route) = self.test_direct_udp(target).await {
            routes.push(udp_route);
        }

        // Try mDNS discovery on local network
        if let Ok(mdns_route) = self.discover_mdns_peer(target).await {
            routes.push(mdns_route);
        }

        // Try NAT traversal techniques
        if let Ok(nat_routes) = self.establish_nat_traversal(target).await {
            routes.extend(nat_routes);
        }

        // Always include email fallback
        routes.push(TransportRoute::StandardEmail {
            estimated_latency_min: 1, // 1+ minute typical email latency
        });

        Ok(routes)
    }

    /// WASM stub for transport discovery
    #[cfg(target_arch = "wasm32")]
    pub async fn discover_transports(&mut self, _target: &str) -> Result<Vec<TransportRoute>> {
        // WASM currently only supports basic message passing
        Ok(vec![TransportRoute::WebAssembly {
            estimated_latency_ms: 50,
        }])
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn test_direct_tcp(&self, target: &str) -> Result<TransportRoute> {
        // Try common ports for EMRP TCP transport
        let ports = vec![8080, 8443, 9090, 7777];

        for port in ports {
            let address = format!("{target}:{port}");
            let start = Instant::now();

            match timeout(
                self.discovery_timeout,
                tokio::net::TcpStream::connect(&address),
            )
            .await
            {
                Ok(Ok(_stream)) => {
                    let latency = start.elapsed();
                    return Ok(TransportRoute::DirectTcp {
                        address: target.to_string(),
                        port,
                        latency_ms: latency.as_millis() as u32,
                        established_at: Instant::now(),
                    });
                }
                _ => continue,
            }
        }

        Err(crate::error::SynapseError::TransportError(
            "No direct TCP connection available".into(),
        ))
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn test_direct_udp(&self, target: &str) -> Result<TransportRoute> {
        // Try common ports for EMRP UDP transport
        let ports = vec![8080, 8443, 9090, 7777];

        for port in ports {
            let address = format!("{target}:{port}");
            let start = Instant::now();
            // Bind loopback for a loopback target, so probing this machine needs no wildcard socket.
            let Some(peer) = tokio::net::lookup_host(&address)
                .await
                .ok()
                .and_then(|mut addrs| addrs.next())
            else {
                continue;
            };

            match timeout(
                self.discovery_timeout,
                tokio::net::UdpSocket::bind(crate::network_scope::outbound_udp_local_addr(&peer)),
            )
            .await
            {
                Ok(Ok(socket)) => {
                    // Test UDP connectivity with a ping packet
                    if socket.connect(&address).await.is_ok() {
                        let latency = start.elapsed();
                        return Ok(TransportRoute::DirectUdp {
                            address: target.to_string(),
                            port,
                            latency_ms: latency.as_millis() as u32,
                            established_at: Instant::now(),
                        });
                    }
                }
                _ => continue,
            }
        }

        Err(crate::error::SynapseError::TransportError(
            "No direct UDP connection available".into(),
        ))
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn discover_mdns_peer(&self, _target: &str) -> Result<TransportRoute> {
        // mDNS discovery implementation will be in mdns.rs
        // For now, return an error indicating it's not available
        Err(crate::error::SynapseError::TransportError(
            "mDNS discovery not yet implemented".into(),
        ))
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn establish_nat_traversal(&self, _target: &str) -> Result<Vec<TransportRoute>> {
        // NAT traversal implementation will be in nat_traversal.rs
        // For now, return empty vec
        Ok(Vec::new())
    }
}

/// Transport selection algorithm
pub struct TransportSelector {
    discovery: TransportDiscovery,
    performance_weights: TransportWeights,
}

#[derive(Debug, Clone)]
pub struct TransportWeights {
    pub latency_weight: f32,
    pub reliability_weight: f32,
    pub throughput_weight: f32,
    pub setup_time_weight: f32,
}

impl Default for TransportWeights {
    fn default() -> Self {
        Self {
            latency_weight: 0.4,
            reliability_weight: 0.3,
            throughput_weight: 0.2,
            setup_time_weight: 0.1,
        }
    }
}

impl Default for TransportSelector {
    fn default() -> Self {
        Self::new()
    }
}

impl TransportSelector {
    pub fn new() -> Self {
        Self {
            discovery: TransportDiscovery::new(),
            performance_weights: TransportWeights::default(),
        }
    }

    /// Choose the optimal transport for a message (non-WASM platforms)
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn choose_optimal_transport(
        &mut self,
        target: &str,
        urgency: abstraction::MessageUrgency,
    ) -> Result<TransportRoute> {
        let available_routes = self.discovery.discover_transports(target).await?;

        match urgency {
            abstraction::MessageUrgency::Critical | abstraction::MessageUrgency::RealTime => {
                // Only use transports with <100ms latency
                for route in available_routes {
                    match route {
                        TransportRoute::DirectTcp { latency_ms, .. }
                        | TransportRoute::DirectUdp { latency_ms, .. }
                        | TransportRoute::LocalMdns { latency_ms, .. }
                        | TransportRoute::NatTraversal { latency_ms, .. }
                            if latency_ms < 100 =>
                        {
                            return Ok(route);
                        }
                        _ => continue,
                    }
                }
                Err(crate::error::SynapseError::TransportError(
                    "No real-time transport available".into(),
                ))
            }
            abstraction::MessageUrgency::Interactive => {
                // Accept up to 1s latency, prefer faster options
                self.select_best_route(available_routes, 1000).await
            }
            abstraction::MessageUrgency::Background | abstraction::MessageUrgency::Batch => {
                // Prefer reliability over speed
                self.select_most_reliable_route(available_routes).await
            }
        }
    }

    /// Choose the optimal transport for a message (WASM platforms)
    #[cfg(target_arch = "wasm32")]
    pub async fn choose_optimal_transport(
        &mut self,
        _target: &str,
        _urgency: abstraction::MessageUrgency,
    ) -> Result<TransportRoute> {
        // WASM currently only supports basic message passing
        Ok(TransportRoute::WebAssembly {
            estimated_latency_ms: 50,
        })
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn select_best_route(
        &self,
        routes: Vec<TransportRoute>,
        max_latency_ms: u32,
    ) -> Result<TransportRoute> {
        let mut best_route = None;
        let mut best_score = f32::MIN;

        for route in routes {
            let latency_ms = self.get_route_latency(&route);
            if latency_ms <= max_latency_ms {
                let score = self.calculate_route_score(&route);
                if score > best_score {
                    best_score = score;
                    best_route = Some(route);
                }
            }
        }

        best_route.ok_or_else(|| {
            crate::error::SynapseError::TransportError("No suitable transport found".into())
        })
    }

    #[cfg(not(target_arch = "wasm32"))]
    async fn select_most_reliable_route(
        &self,
        routes: Vec<TransportRoute>,
    ) -> Result<TransportRoute> {
        // Prefer email and other reliable transports
        for route in &routes {
            match route {
                TransportRoute::StandardEmail { .. } => return Ok(route.clone()),
                TransportRoute::FastEmailRelay { .. } => return Ok(route.clone()),
                _ => continue,
            }
        }

        // If no email available, use the best alternative
        self.select_best_route(routes, u32::MAX).await
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn get_route_latency(&self, route: &TransportRoute) -> u32 {
        match route {
            TransportRoute::DirectTcp { latency_ms, .. }
            | TransportRoute::DirectUdp { latency_ms, .. }
            | TransportRoute::LocalMdns { latency_ms, .. }
            | TransportRoute::NatTraversal { latency_ms, .. } => *latency_ms,
            TransportRoute::FastEmailRelay {
                estimated_latency_ms,
                ..
            } => *estimated_latency_ms,
            TransportRoute::StandardEmail {
                estimated_latency_min,
            } => estimated_latency_min * 60 * 1000, // Convert minutes to ms
            TransportRoute::EmailDiscovery { .. } => 30_000, // 30s for discovery
            TransportRoute::Udp { .. } => 5,                 // 5ms estimated for UDP
            TransportRoute::WebSocket { .. } => 20,          // 20ms estimated for WebSocket
            TransportRoute::Quic { .. } => 10,               // 10ms estimated for QUIC
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn calculate_route_score(&self, route: &TransportRoute) -> f32 {
        let latency_ms = self.get_route_latency(route) as f32;
        let reliability = self.get_route_reliability(route);
        let setup_time = self.get_route_setup_time(route);

        // Lower latency and setup time = higher score
        // Higher reliability = higher score
        let latency_score = 1.0 / (1.0 + latency_ms / 1000.0); // Normalize to 0-1
        let setup_score = 1.0 / (1.0 + setup_time);

        latency_score * self.performance_weights.latency_weight
            + reliability * self.performance_weights.reliability_weight
            + setup_score * self.performance_weights.setup_time_weight
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn get_route_reliability(&self, route: &TransportRoute) -> f32 {
        match route {
            TransportRoute::StandardEmail { .. } => 0.95,
            TransportRoute::FastEmailRelay { .. } => 0.90,
            TransportRoute::DirectTcp { .. } => 0.85,
            TransportRoute::DirectUdp { .. } => 0.80,
            TransportRoute::LocalMdns { .. } => 0.95,
            TransportRoute::NatTraversal { .. } => 0.70,
            TransportRoute::EmailDiscovery { .. } => 0.95,
            TransportRoute::Udp { .. } => 0.80,
            TransportRoute::WebSocket { .. } => 0.85,
            TransportRoute::Quic { .. } => 0.90,
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn get_route_setup_time(&self, route: &TransportRoute) -> f32 {
        match route {
            TransportRoute::DirectTcp { .. } => 0.1,       // 100ms
            TransportRoute::DirectUdp { .. } => 0.05,      // 50ms
            TransportRoute::LocalMdns { .. } => 0.05,      // 50ms
            TransportRoute::NatTraversal { .. } => 2.0,    // 2s
            TransportRoute::FastEmailRelay { .. } => 1.0,  // 1s
            TransportRoute::StandardEmail { .. } => 1.0,   // 1s
            TransportRoute::EmailDiscovery { .. } => 30.0, // 30s
            TransportRoute::Udp { .. } => 0.05,            // 50ms
            TransportRoute::WebSocket { .. } => 0.2,       // 200ms
            TransportRoute::Quic { .. } => 0.1,            // 100ms
        }
    }
}

// Re-export all major components for easy access
pub use abstraction::*;
pub use manager::*;
pub use security::KnockLimits;

#[cfg(not(target_arch = "wasm32"))]
// Removed unexpected cfg feature condition
pub use http_unified::{HttpTransportFactory, HttpTransportImpl};
#[cfg(not(target_arch = "wasm32"))]
pub use udp_unified::{UdpTransportFactory, UdpTransportImpl};

// Platform-specific re-exports (only on non-WASM platforms)
#[cfg(all(feature = "email", not(target_arch = "wasm32")))]
pub use email_unified::{EmailTransportFactory, EmailTransportImpl};
#[cfg(not(target_arch = "wasm32"))]
pub use llm_discovery::{
    DiscoveredLlm, LlmConnection, LlmConnectionInfo, LlmDiscoveryConfig, LlmDiscoveryManager,
    LlmModelInfo, LlmPerformanceMetrics, LlmRequest, LlmResponse, LlmResponseMetadata, LlmStatus,
};
#[cfg(not(target_arch = "wasm32"))]
pub use mdns_enhanced::{EnhancedMdnsTransport, MdnsConfig};
#[cfg(not(target_arch = "wasm32"))]
pub use nat_traversal::{IceCandidate, NatTraversalTransport};
// The QUIC transport that listens and receives. Named explicitly, matching `tcp_unified`'s
// re-export just below: `abstraction` once defined a second `QuicTransportFactory` that the
// glob re-export above would otherwise shadow.
#[cfg(not(target_arch = "wasm32"))]
pub use quic_unified::{QuicTransportFactory, QuicTransportImpl};
#[cfg(not(target_arch = "wasm32"))]
pub use router::MultiTransportRouter;
// The TCP transport that listens and receives. Named explicitly: `abstraction` once defined a
// second `TcpTransportFactory` that the glob re-export above made public in its place.
#[cfg(not(target_arch = "wasm32"))]
pub use tcp_unified::{TcpTransportFactory, TcpTransportImpl};
#[cfg(not(target_arch = "wasm32"))]
pub use websocket_unified::WebSocketTransportImpl;
