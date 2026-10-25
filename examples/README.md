# 🚀 Synapse Examples

This directory contains practical examples demonstrating how to use the Synapse neural communication network in real-world scenarios.

## 📚 Available Examples

### Basic Examples

- [`hello_world.rs`](hello_world.rs) - Simplest possible Synapse application
- [`working_basic_chat.rs`](working_basic_chat.rs) - Two-way communication example
- [`simple_working_demo.rs`](simple_working_demo.rs) - Core features demonstration

### Fixed and Working Examples

- [`basic_chat_fixed.rs`](basic_chat_fixed.rs) - Fixed version of basic chat
- [`connectivity_demo_fixed.rs`](connectivity_demo_fixed.rs) - Network connectivity handling
- [`tool_interaction_fixed.rs`](tool_interaction_fixed.rs) - AI tool use framework

### Transport Examples

- [`unified_transport_demo.rs`](unified_transport_demo.rs) - Unified transport layer demonstration
- [`multi_transport_demo.rs`](multi_transport_demo.rs) - Using multiple transport types
- [`email_server_demo.rs`](email_server_demo.rs) - Email server integration

### Fault Tolerance Examples

- [`circuit_breaker_demo.rs`](circuit_breaker_demo.rs) - Circuit breaker pattern implementation
- [`multi_transport_circuit_breaker_demo.rs`](multi_transport_circuit_breaker_demo.rs) - Circuit breakers with multiple transports

### Identity Resolution Examples

- [`simple_unknown_name_resolution.rs`](simple_unknown_name_resolution.rs) - Basic unknown contact handling

### AI and LLM Examples

- [`llm_discovery_demo.rs`](llm_discovery_demo.rs) - LLM service discovery and connection
- [`synapse_ai_network.rs`](synapse_ai_network.rs) - Advanced multi-LLM coordination

### Testing Examples

- [`comprehensive_test.rs`](comprehensive_test.rs) - Comprehensive feature testing
- [`production_readiness_test.rs`](production_readiness_test.rs) - Production readiness validation

### Transport Testing

- [`basic_unified_transport_test.rs`](basic_unified_transport_test.rs) - Basic transport testing
- [`unified_transport_test.rs`](unified_transport_test.rs) - Unified transport testing

### Email Integration

- [`email_integration_test.rs`](email_integration_test.rs) - Email system integration testing

### Enhanced Features

- [`enhanced_router_demo.rs`](enhanced_router_demo.rs) - Advanced routing capabilities

## 🏃 Quick Start

1. **Clone and build the project**:

   ```bash
   git clone <repository-url>
   cd synapse
   cargo build --examples
   ```

2. **Run the hello world example**:

   ```bash
   cargo run --example hello_world
   ```

3. **Try the working chat example**:

   ```bash
   cargo run --example working_basic_chat
   ```

## 🛠️ Running Examples

Each example can be run with:

```bash
cargo run --example <example_name>
```

Some examples accept command-line arguments. Use `--help` to see options:

```bash
cargo run --example basic_chat_fixed -- --help
```

## 📋 Example Descriptions

### hello_world.rs

The simplest Synapse application - demonstrates basic setup and message creation.
**Concepts:** Basic setup, message creation, minimal configuration

### working_basic_chat.rs

Interactive chat demonstration with proper message routing.
**Concepts:** Bidirectional communication, message handling, user interaction

### simple_working_demo.rs

Core Synapse features demonstration.
**Concepts:** Identity management, message routing, transport abstraction

### basic_chat_fixed.rs

Fixed version of basic chat with proper error handling.
**Concepts:** Error handling, robust communication, message validation

### connectivity_demo_fixed.rs

Network connectivity handling with fallback mechanisms.
**Concepts:** Network resilience, connectivity monitoring, transport failover

### tool_interaction_fixed.rs

AI tool use framework with proper message serialization.
**Concepts:** Structured messaging, tool integration, AI communication

### unified_transport_demo.rs

Unified transport layer demonstration showing multiple transport types.
**Concepts:** Transport abstraction, protocol switching, unified interface

### multi_transport_demo.rs

Using multiple transport types intelligently with selection logic.
**Concepts:** Transport selection, fallback mechanisms, performance optimization

### circuit_breaker_demo.rs

Circuit breaker pattern implementation for fault tolerance.
**Concepts:** Fault tolerance, circuit breaker pattern, error recovery

### email_server_demo.rs

Email server integration with external email providers.
**Concepts:** SMTP/IMAP configuration, email fallback, hybrid operation

### llm_discovery_demo.rs

LLM service discovery and connection management.
**Concepts:** Service discovery, LLM integration, capability negotiation

### synapse_ai_network.rs

Advanced multi-LLM coordination and task distribution.
**Concepts:** AI coordination, task distribution, multi-agent systems

### comprehensive_test.rs

Comprehensive feature testing covering all major components.
**Concepts:** Integration testing, feature validation, system testing

### production_readiness_test.rs

Production readiness validation with performance and reliability checks.
**Concepts:** Production validation, performance testing, reliability checks

### simple_unknown_name_resolution.rs

Demonstrates basic patterns for contacting unknown people using Synapse's smart resolution.
**Concepts:** Unknown contact resolution, contextual hints, auto-approval, fuzzy matching

## 🎯 Learning Path

**Recommended order for learning:**

1. **Start with `hello_world.rs`** - Understand basic concepts
2. **Try `working_basic_chat.rs`** - Learn bidirectional communication  
3. **Explore `simple_working_demo.rs`** - See core features
4. **Study `unified_transport_demo.rs`** - Understand transport intelligence
5. **Examine `tool_interaction_fixed.rs`** - Learn structured communication
6. **Review `email_server_demo.rs`** - Master email integration
7. **Advanced examples** - Based on your specific use case

## 🔧 Customizing Examples

All examples are designed to be easily modified. Common customizations:

### Change Configuration

```rust
let config = SynapseConfig::builder()
    .entity_name("my_entity".to_string())
    .entity_type("custom".to_string())
    .build();
```

### Enable Different Features

```rust
let config = SynapseConfig::builder()
    .enable_discovery(true)
    .enable_encryption(true)
    .build();
```

### Add Email Configuration

```rust
let config = SynapseConfig::builder()
    .email_address("your_email@domain.com".to_string())
    .smtp_server("smtp.domain.com".to_string())
    .build();
```

## 🧪 Testing Examples

Most examples can be run in test mode or with verbose logging:

```bash
RUST_LOG=debug cargo run --example hello_world
```

## 📖 Additional Resources

- **[Developer Guide](../docs/DEVELOPER_GUIDE.md)** - Comprehensive development guide
- **[Configuration Guide](../docs/CONFIGURATION_GUIDE.md)** - All configuration options
- **[Troubleshooting](../docs/TROUBLESHOOTING.md)** - Common issues and solutions
- **[Working Examples Guide](WORKING_EXAMPLES_GUIDE.md)** - Guide to all working examples

## 🤝 Contributing Examples

Want to add your own example? Great! Please:

1. Follow the existing code style
2. Include comprehensive comments
3. Add proper error handling
4. Update this README with your example
5. Test on multiple platforms

See `CONTRIBUTING.md` for detailed guidelines.

---

**Happy coding with Synapse! 🎉**
