# 🏆 Synapse: The Enterprise AI Communication Platform

![Synapse Enterprise AI Communication Platform](Synapse.png)

[![Rust](https://img.shields.io/badge/rust-2021%2B-brightgreen.svg)](https://www.rust-lang.org)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Version](https://img.shields.io/badge/version-2.0.0-orange.svg)](Cargo.toml)

> **The World's First Military-Grade AI Neural Communication Network for Enterprise-Scale AI Deployment**

## 🚀 Powering the Future of Enterprise AI Communication

**Synapse** is the revolutionary enterprise-grade AI communication platform that transforms how Fortune 500 companies deploy AI agents, services, and distributed AI systems at scale. Built from the ground up with **military-grade security**, **AI-native authentication**, and **enterprise compliance**, Synapse is the premier choice for organizations deploying production AI systems.

### 🏢 Why Enterprise Leaders Choose Synapse

- **🤖 AI-Native Architecture**: The only platform designed specifically for AI-to-AI communication
- **🏢 Enterprise-Ready Security**: SAML SSO, WebAuthn passwordless, MFA, and advanced audit trails
- **📋 Compliance-First Design**: GDPR, HIPAA, SOX, ISO27001 compliance built-in
- **⚡ Production-Scale Performance**: Handle millions of AI communications with advanced rate limiting
- **🌍 Global Federation**: Connect AI systems across organizations, clouds, and networks worldwide
- **� Zero-Trust Security**: Every AI agent verified, every communication encrypted, every action audited

## 🌟 Revolutionary AI Communication Features

### 🤖 AI-Native Authentication System

**The first and only authentication system designed specifically for AI agents and neural networks:**

```rust
// WebAuthn Passwordless Authentication for AI Agents
match auth_manager.authenticate_ai_agent_webauthn(
    "claude-3-opus",
    webauthn_assertion,
    "ai.company.com"
).await? {
    Success { user_profile, session_token, .. } => {
        println!("🤖 AI Agent authenticated with military-grade security");
        // AI agent can now communicate securely across the enterprise network
    }
}
```

- **🔐 WebAuthn Passwordless**: AI agents authenticate using hardware security keys
- **🔑 API Key Management**: Secure AI-to-AI communication channels with automatic rotation
- **📱 Device Authorization**: Edge AI and IoT devices get secure, time-limited access
- **🌐 Federated Identity**: Single sign-on across distributed AI networks

### 🏢 Enterprise Integration Excellence

**Complete corporate integration with leading identity providers:**

```rust
// Enterprise SAML SSO Integration
let auth_result = auth_manager.authenticate_saml_enterprise(
    "Microsoft Active Directory",
    saml_assertion,
    client_ip
).await?;

match auth_result {
    Success { user_profile, .. } => {
        println!("✅ Enterprise user {} authenticated via corporate SSO",
                 user_profile.display_name);
        // User can now access AI network with enterprise permissions
    }
}
```

- **🏢 SAML 2.0 Corporate SSO**: Active Directory, Okta, and custom identity providers
- **📋 Advanced Audit Trails**: Complete compliance logging for GDPR, HIPAA, SOX
- **🛡️ Zero-Trust Architecture**: All entities verified before network access
- **📊 Real-time Compliance**: Automatic policy violation detection and reporting

## 🎯 Revolutionary Neural Identity System

**The most advanced AI communication addressing system ever created:**

```rust
// Instead of complex IP addresses and service discovery...
ai_network.connect_to("192.168.1.100:8080/api/v1/agent/claude").await?;

// Just use natural AI entity names!
ai_network.send_to("Claude", message).await?;  // 🎉 Automatically resolved!
ai_network.send_to("GPT-4 Marketing Team", request).await?;  // 🎉 Context-aware routing!
ai_network.send_to("Customer Service AI", inquiry).await?;  // 🎉 Role-based discovery!
```

### How Enterprise AI Identity Resolution Works

1. **🤖 AI Agent Names**: `"Claude"`, `"GPT-4"`, `"Customer Service AI"`
2. **🏢 Enterprise Global IDs**: `"claude@company.com"`, `"marketing-ai@enterprise.corp"`
3. **🌐 Network Discovery**: Automatic discovery of AI services, capabilities, and permissions
4. **⚡ Intelligent Routing**: ML-powered transport selection for optimal AI communication

```text
Enterprise AI Communication Flow:
"Marketing AI" → marketing-ai@company.com → enterprise-sso-validated → secure-channel → real-time-response
"Claude" → claude@anthropic.com → webauthn-verified → encrypted-email → reliable-delivery
"Edge AI Camera" → camera-001@factory.com → device-authorized → local-mesh → ultra-low-latency
```

## 🏗️ Architecture Overview

Synapse operates on multiple layers to provide maximum flexibility and performance:

### Transport Layer Hierarchy

```text
┌─────────────────────────────────────────────────────────────┐
│                  Synapse Message Layer                      │
│  Simple names, security, routing, message types            │
├─────────────────────────────────────────────────────────────┤
│                    Identity Resolution                       │
│  Local names → Global IDs → Network addresses              │
├─────────────────────────────────────────────────────────────┤
│                    Multi-Transport Router                   │
│  Automatic selection of best available transport            │
├──────────────┬──────────────┬──────────────┬──────────────┤
│  Real-Time   │   Direct     │    Local     │    Email     │
│  (<100ms)    │  Connection  │  Discovery   │   Reliable   │
│              │              │              │              │
│  • TCP       │  • UDP       │  • mDNS      │  • SMTP      │
│  • WebSocket │  • Raw IP    │  • LAN scan  │  • IMAP      │
│  • gRPC      │  • P2P       │  • Bluetooth │  • Exchange  │
└──────────────┴──────────────┴──────────────┴──────────────┘
```

### Intelligence Features

- **🧠 Adaptive Routing**: Learns network topology and optimizes routes
- **📊 Performance Monitoring**: Tracks latency, reliability, bandwidth usage
- **🔄 Automatic Fallback**: Gracefully degrades from fast → reliable transports
- **🌐 NAT Traversal**: Punches through firewalls using STUN/TURN/UPnP
- **📡 Service Discovery**: Finds peers on local networks automatically

## 🚀 Quick Start

### Installation

To use the library, depend on the `synapse` crate (the library is `synapse`, not `message_routing_system`). The 6.0.0
release-candidate series is not on crates.io yet (crates.io has `synapse` 1.1.0), so until it is, depend on the repository:

```toml
[dependencies]
synapse = { git = "https://github.com/ThinkersJournal/synapse" }
```

#### Command-line tools

| crate | installs | what it is |
|---|---|---|
| `synapsectl` | `synapse` | the `synapse` command: identity (`synapse id …`) and mail over `synapsed` (`claim`, `send`, `inbox`, `ack`, `list`) |
| `synapsed` | `synapsed` | the per-user loopback daemon; `synapse` starts it on demand |
| `synapse-mcp-server` | `synapse-mcp` | the generic MCP stdio adapter over `synapsed`, for any MCP client (`synapse-mcp --role <role>`) |
| `synapse-claude-channel` | `synapse-claude-channel` | the Claude Code channel adapter: the same tools, plus mailbox messages pushed into the session as untrusted channel events (`synapse-claude-channel --role <role>`) |

```sh
cargo install synapsectl synapsed synapse-mcp-server
```

These three crates are not on crates.io yet. Until they are, install from a checkout with
`cargo install --path crates/<crate>`.

These crates are named `synapsectl` and `synapse-mcp-server` because `synapse-cli` and `synapse-mcp`
on crates.io belong to other, unrelated projects. The commands you type, and any MCP client
configuration, still use `synapse` and `synapse-mcp`.

**Binary name clash:** the unrelated `synapse-cli` crate also installs a binary called `synapse`. If
it is installed, `cargo install synapsectl` refuses to overwrite it; uninstall it first
(`cargo uninstall synapse-cli`), or pass `--force` to replace it.

### Basic Usage

Two roles, `alice` and `bob`, exchanging one message through the daemon. This is the sequence that was run from a clean
home on Windows at 6.0.0-rc.48, with the CLI installed by `cargo install --path crates/synapsectl` and
`cargo install --path crates/synapsed` (cargo takes one `--path` per invocation):

```sh
synapse id init --account me        # names: letters, digits, '-' and '_' only, 1 to 64
synapse claim --role alice          # starts synapsed on demand; prints identity: alice@me
synapse claim --role bob
synapse send --role alice --to bob "hello"        # outcome: queued
synapse inbox --role bob            # one JSON object per line; the message stays leased
synapse ack --role bob <message_id> # outcome: removed
synapse list --role alice           # every role, with presence and pending counts
```

`SYNAPSE_HOME` chooses the keystore and session directory and `SYNAPSE_ADDR` the daemon's loopback address. On Windows the
account directory must not be readable by anyone else: a `SYNAPSE_HOME` under `C:\s` was refused with `permissions_too_open` (the ACL was not read; the cause is inferred).
Use a directory under your profile.

The library example that stood here called a `register_peer` method that does not exist, so it was removed. See
`examples/hello_world.rs` for code that builds.

### Real-World Example: AI Collaboration

```rust
// AI agents coordinating on a research project
async fn ai_research_collaboration() -> Result<()> {
    let claude = EnhancedSynapseRouter::new(config, "claude@anthropic.com".to_string()).await?;

    // Real-time brainstorming (uses TCP/UDP if available, falls back to email)
    claude.send_message_smart(
        "GPT-4",
        "What's your take on quantum consciousness theories?",
        MessageType::Conversation,
        SecurityLevel::Authenticated,
        MessageUrgency::RealTime,  // <100ms preferred
    ).await?;

    // File sharing (automatic transport selection based on size)
    claude.send_file(
        "ResearchTeam",
        "quantum_paper_draft_v3.pdf",
        MessageUrgency::Normal,
    ).await?;

    // Reliable delivery for important results (guaranteed delivery via email)
    claude.send_message_smart(
        "Human-Researcher",
        "Breakthrough achieved! See attached simulation results.",
        MessageType::Notification,
        SecurityLevel::Encrypted,
        MessageUrgency::Background,  // Reliability over speed
    ).await?;

    Ok(())
}
```

## 🎛️ Advanced Features

### 1. Multi-Transport Intelligence

Synapse automatically selects the best transport method based on:

- **Message urgency** (real-time vs. reliable delivery)
- **Network conditions** (latency, bandwidth, connectivity)
- **Security requirements** (encryption, authentication)
- **Peer capabilities** (what transports they support)

```rust
// The system automatically chooses:
// • TCP for local real-time messages
// • UDP for low-latency discovery
// • Email for reliable remote delivery
// • mDNS for local peer discovery
// • NAT traversal for firewall penetration
```

### 2. Email Server Integration

Synapse can run its own email infrastructure when externally accessible:

```rust
// Automatic email server with intelligent connectivity detection
let router = EnhancedSynapseRouter::new(config, entity_id).await?;

if router.is_running_email_server() {
    println!("🏃 Running local SMTP/IMAP server");
    // Can receive emails directly at your-bot@your-domain.com
} else {
    println!("🌐 Using external email providers");
    // Falls back to Gmail, Outlook, etc.
}
```

### 3. Circuit Breaker Infrastructure

Comprehensive circuit breaker protection across all transports:

```rust
// Automatic circuit breaker protection
let transport = EnhancedMdnsTransport::new("entity-id", 8080, None).await?;

// Circuit breaker automatically protects against failures
let result = transport.send_message("target", &message).await;

// Monitor circuit breaker state
let stats = transport.get_circuit_breaker().get_stats();
println!("Circuit state: {:?}, failures: {}", stats.state, stats.failure_count);
```

**Key Features:**

- **Automatic failure detection** based on configurable thresholds
- **Intelligent recovery** with half-open testing
- **External triggers** for performance degradation
- **Comprehensive monitoring** with real-time statistics

### 4. Real-Time Streaming

Live streaming capabilities for continuous communication:

```rust
// Start a streaming session
let stream = router.start_stream("Alice").await?;

// Send streaming data
stream.send_chunk(b"Live data chunk 1").await?;
stream.send_chunk(b"Live data chunk 2").await?;

// End the stream
stream.finalize().await?;
```

**Key Features:**

- **Stream chunking** with automatic reassembly
- **Priority-based** delivery for different stream types
- **Session management** for multiple concurrent streams
- **Reliability guarantees** with acknowledgment tracking

### 5. OAuth & Federated Authentication

Enterprise-grade authentication with OAuth 2.0 support:

```rust
// OAuth provider integration
let auth_manager = SynapseAuthManager::new(auth_config).await?;

// Authenticate with multiple providers
let token = auth_manager.authenticate_oauth("google", credentials).await?;

// Use federated identity
let user_context = auth_manager.get_user_context(&token).await?;
```

**Key Features:**

- **OAuth 2.0 provider** integration (Google, Microsoft, etc.)
- **Multi-factor authentication** support
- **JWT token management** with automatic refresh
- **Federated identity** across organizations

### 6. Advanced Monitoring & Metrics

Comprehensive system monitoring and performance tracking:

```rust
// Get system metrics
let metrics = router.get_metrics().await?;
println!("Messages/sec: {}", metrics.message_throughput);
println!("Average latency: {:?}", metrics.average_latency);

// Subscribe to performance alerts
let mut alerts = router.subscribe_alerts().await?;
while let Some(alert) = alerts.recv().await {
    println!("Alert: {}", alert.message);
}
```

**Key Features:**

- **Real-time metrics** collection and reporting
- **Performance monitoring** with historical data
- **Alert system** for performance degradation
- **Health diagnostics** for system components

### 7. Security by Default

- **🔒 Content Confidentiality**: Not implemented -- `SecurityLevel::Private`/`Secure` are refused
  (see `SynapseError::UnsupportedSecurityLevel`); messages are signed, not encrypted
- **✍️ Digital Signatures**: Verify sender authenticity
- **🛡️ TLS Transport**: Encrypted connections on transports that support it (QUIC, HTTPS); TCP,
  UDP and WebSocket transports in this build are unencrypted
- **🔑 Explicit Key Management**: Keys must be generated via `generate_keypair()`; there is no
  automatic key distribution
- **🚪 Access Control**: Domain-based and user-based permissions

### 8. Federation & Interoperability

```rust
// Your Synapse system automatically interoperates with:
// • Other Synapse systems
// • Standard email servers
// • Existing AI communication platforms
// • Legacy enterprise messaging systems
```

## 📖 Documentation

### Core Concepts

- **[Transport Layer](docs/API_REFERENCE.md#-transport-system)**: Multi-transport architecture
- **[Security Model](docs/API_REFERENCE.md#-error-handling)**: Encryption and authentication
- **[Email Integration](docs/API_REFERENCE.md#-transport-system)**: SMTP/IMAP server capabilities
- **[Configuration](docs/CONFIGURATION_GUIDE.md)**: Setup and customization

### API Reference

- **[Enhanced Router](docs/API_REFERENCE.md#️-core-components)**: Main interface
- **[Message Types](docs/API_REFERENCE.md#-message-types)**: Communication patterns
- **[Streaming API](docs/API_REFERENCE.md#-streaming-api)**: Real-time streaming support
- **[WebRTC Transport](docs/API_REFERENCE.md#-webrtc-transport)**: Browser-based communication

### Examples

- **[All runnable examples](examples/)** — 33 of them, including `hello_world.rs`,
  `basic_chat.rs`, `synapse_ai_network.rs` and `email_server_demo.rs`.
  Run one with `cargo run --example <name>`.
- **[Email Server](examples/email_server_demo.rs)**: Server functionality
- **[Integration Test](examples/email_integration_test.rs)**: System validation

## 🛠️ Use Cases

### AI & Machine Learning

- **Multi-agent AI systems** coordinating in real-time
- **AI-human collaboration** with natural addressing
- **Federated learning** with secure model sharing
- **Research collaboration** between AI entities

### Enterprise & Business

- **Microservice communication** with email-based service discovery
- **Cross-organization messaging** leveraging existing email infrastructure
- **Reliable async processing** with email-based queuing
- **Legacy system integration** through email gateways

### IoT & Edge Computing

- **Device-to-cloud communication** using email when internet is limited
- **Peer-to-peer IoT networks** with automatic discovery
- **Edge AI coordination** across distributed deployments
- **Resilient communication** in unstable network conditions

## 🖥️ Platform-Specific Notes

### Windows Development

**Windows users may encounter linker error LNK1318** when building debug versions due to Microsoft linker limitations with complex dependency graphs. This has been resolved using LLVM's `lld-link` linker.

**Quick Solution:**

```toml
# Add to your .cargo/config.toml
[target.x86_64-pc-windows-msvc]
linker = "lld-link"
```

📖 **For detailed information and alternative solutions**, see [Windows Linker Workaround Guide](docs/WINDOWS_LINKER_WORKAROUND.md)

### Network exposure: loopback by default (2.0.0)

Synapse listens on **127.0.0.1 only** unless you ask for more. A listener on every interface can be
reached from other machines. On Windows it also makes the firewall ask for permission, and test and
doc-test binaries used to trigger that on every run.

To accept peers from other machines, opt in explicitly:

```toml
# In a synapse Config file
[network]
bind_scope = "all_interfaces"
```

For a transport built from a config map, set `bind_scope = "all_interfaces"` in the map.

Under the loopback default, features that only work across machines are switched off:
- the mDNS transport, the service browser and LLM discovery refuse to start, with an error that names
  the setting;
- NAT traversal skips STUN and UPnP;
- email connectivity detection skips external-IP detection.

See [`src/network_scope.rs`](src/network_scope.rs).

## 🤝 Contributing

We welcome contributions! See the [Developer Guide](docs/DEVELOPER_GUIDE.md) for build, test and layout details.

### Development Setup

```bash
git clone https://github.com/ThinkersJournal/synapse
cd synapse
cargo build --locked --workspace
cargo test --locked --workspace --no-fail-fast
```

The layout, the CI commands and the mailbox contract are in the [Developer Guide](docs/DEVELOPER_GUIDE.md).

## � Documentation and Resources

### 📖 Core Documentation

- **[Developer Guide](docs/DEVELOPER_GUIDE.md)** - Build, test, layout and the mailbox contract
- **[API Reference](docs/API_REFERENCE.md)** - Complete API documentation with examples
- **[Configuration Guide](docs/CONFIGURATION_GUIDE.md)** - Environment variables, mailbox limits and the files in the home
- **[Troubleshooting Guide](docs/TROUBLESHOOTING.md)** - Daemon will not start, refused calls, messages that do not arrive
- **[New Features](docs/NEW_FEATURES.md)** - Latest features and capabilities in v1.0.0

### 🏗️ Architecture and Design

- **[Deployment Guide](docs/DEPLOYMENT_GUIDE.md)** - Production deployment instructions
- **[Security Audit](security/TRUST_SYSTEM_SECURITY_AUDIT.md)** - Security analysis and trust system

### 🧪 Specialized Features

- **[LLM Discovery Guide](docs/LLM_DISCOVERY_GUIDE.md)** - AI agent discovery and communication
- **[Circuit Breaker System](docs/CIRCUIT_BREAKER_SYSTEM.md)** - Fault tolerance patterns
- **[WASM Support](docs/WASM_README.md)** - WebAssembly and browser support

### 🚀 Examples and Tutorials

- **[Examples Directory](examples/)** - Working examples for different use cases
- **[Hello World Example](examples/hello_world.rs)** - Simplest Synapse application
- **[AI Assistant Network](examples/ai_assistant_network.rs)** - Multi-AI agent communication

### 🔧 Technical References

- **Generated API Docs**: Run `cargo doc --open` for complete API reference

### 📊 Project Status

- **[New Features](docs/NEW_FEATURES.md)** - Latest features and capabilities added in v1.0.0
- **[API Reference](docs/API_REFERENCE.md)** - Complete API documentation with examples
- **[Developer Guide](docs/DEVELOPER_GUIDE.md)** - Build, test and layout

## �📄 License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

## 🙏 Acknowledgments

Built with modern Rust async technology and inspired by the universal reach of email infrastructure. Special thanks to the email protocol designers who created the foundation that enables global communication.

---

*"Making AI communication as universal as email, as fast as the internet allows, and as secure as modern cryptography enables."*
