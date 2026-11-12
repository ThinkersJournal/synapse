// SPDX-License-Identifier: MIT OR Apache-2.0
//! High-performance IMAP server for EMRP

use crate::error::{Result, SynapseError};
use crate::types::SecureMessage;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info};

use super::security::{EmailSecurity, LoginLimits};

/// High-performance IMAP server optimized for EMRP
pub struct SynapseImapServer {
    /// Server configuration
    config: ImapServerConfig,
    /// Message store (shared with SMTP server)
    message_store: Arc<Mutex<HashMap<String, Vec<SecureMessage>>>>,
    /// Connected clients
    clients: Arc<Mutex<HashMap<String, ImapSession>>>,
    /// Authorization handler
    auth_handler: Arc<dyn super::smtp_server::AuthHandler + Send + Sync>,
    /// The login guard and the event sink (hardening P7).
    security: EmailSecurity,
    /// Messages sent in FETCH responses (see [`SynapseImapServer::fetch_counter`]).
    fetched: Arc<std::sync::atomic::AtomicU64>,
}

#[derive(Debug, Clone)]
pub struct ImapServerConfig {
    /// IMAP port (usually 143 or 993)
    pub port: u16,
    /// TLS configuration
    pub tls_config: Option<super::smtp_server::TlsConfig>,
    /// Enable IDLE extension for push notifications
    pub enable_idle: bool,
    /// Performance optimization
    pub performance: ImapPerformanceConfig,
    /// Which interfaces the server listens on (loopback by default)
    pub bind_scope: crate::network_scope::BindScope,
}

#[derive(Debug, Clone)]
pub struct ImapPerformanceConfig {
    /// Maximum concurrent connections
    pub max_connections: usize,
    /// IDLE timeout (seconds)
    pub idle_timeout: u64,
    /// Compression support
    pub enable_compression: bool,
}

#[derive(Debug)]
struct ImapSession {
    /// The peer's IP, the key the login guard uses.
    source: String,
    state: ImapState,
    authenticated_user: Option<String>,
    selected_mailbox: Option<String>,
    idle_mode: bool,
}

#[derive(Debug, PartialEq)]
enum ImapState {
    NotAuthenticated,
    Authenticated,
    Selected,
    Logout,
}

impl Default for ImapServerConfig {
    fn default() -> Self {
        Self {
            port: 1143, // Non-privileged port for development
            tls_config: None,
            enable_idle: true,
            performance: ImapPerformanceConfig {
                max_connections: 100,
                idle_timeout: 1740, // 29 minutes (RFC requirement)
                enable_compression: true,
            },
            bind_scope: crate::network_scope::BindScope::default(),
        }
    }
}

impl SynapseImapServer {
    /// Create a new IMAP server
    pub fn new(
        config: ImapServerConfig,
        message_store: Arc<Mutex<HashMap<String, Vec<SecureMessage>>>>,
        auth_handler: Arc<dyn super::smtp_server::AuthHandler + Send + Sync>,
    ) -> Self {
        Self {
            config,
            message_store,
            clients: Arc::new(Mutex::new(HashMap::new())),
            auth_handler,
            security: EmailSecurity::default(),
            fetched: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// How many messages this server has put on the wire in FETCH responses, across all connections
    /// and clones of it. A poll that fetched nothing new leaves it unchanged, which is how a test
    /// proves a poll's cost does not grow with the mailbox.
    #[must_use]
    pub fn fetch_counter(&self) -> Arc<std::sync::atomic::AtomicU64> {
        Arc::clone(&self.fetched)
    }

    /// Replaces the login guard's tuning for IMAP `LOGIN` (hardening P7). The limits apply with or
    /// without a sink.
    #[must_use]
    pub fn with_login_limits(mut self, limits: LoginLimits) -> Self {
        self.security = self.security.with_login(limits);
        self
    }

    /// Where security events go. The first call wins, and it reaches every clone of this server.
    pub fn set_security_sink(&self, sink: Arc<dyn crate::security_events::SecuritySink>) {
        self.security.set_sink(sink);
    }

    /// Shares one set of limiters with a paired SMTP server, so guesses split across the two still
    /// count against one budget.
    pub(crate) fn with_security(mut self, security: EmailSecurity) -> Self {
        self.security = security;
        self
    }

    /// The guard this server checks logins against, for tests of the shared budget.
    #[cfg(test)]
    pub(crate) fn security(&self) -> &EmailSecurity {
        &self.security
    }

    /// Start the IMAP server
    pub async fn start(&self) -> Result<()> {
        let addr = self.config.bind_scope.listen_addr(self.config.port);
        let listener = TcpListener::bind(&addr).await.map_err(|e| {
            SynapseError::NetworkError(format!("Failed to bind IMAP server to {addr}: {e}"))
        })?;

        info!("EMRP IMAP Server listening on {}", addr);

        self.serve(listener).await
    }

    /// Accept connections on an already-bound `listener` forever, as `SynapseSmtpServer::serve`
    /// does, so a caller can hold the port before serving it.
    pub async fn serve(&self, listener: TcpListener) -> Result<()> {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    info!("New IMAP connection from {}", addr);

                    // Handle connection in background task
                    let server = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = server.handle_connection(stream).await {
                            error!("IMAP connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept IMAP connection: {}", e);
                }
            }
        }
    }

    /// Handle individual IMAP connection
    async fn handle_connection(&self, stream: TcpStream) -> Result<()> {
        let source = super::security::source_ip(stream.peer_addr());
        let (read_half, write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);
        let mut writer = write_half;

        let mut session = ImapSession {
            source,
            state: ImapState::NotAuthenticated,
            authenticated_user: None,
            selected_mailbox: None,
            idle_mode: false,
        };

        // Send greeting
        writer.write_all(b"* OK EMRP IMAP Server Ready\r\n").await?;
        writer.flush().await?;

        let mut line = String::new();
        while reader.read_line(&mut line).await? > 0 {
            let command = line.trim();
            debug!("IMAP command: {}", command);

            let responses = self.process_imap_command(command, &mut session).await?;

            for response in responses {
                writer.write_all(response.as_bytes()).await?;
            }
            writer.flush().await?;

            // Check if connection should close
            if session.state == ImapState::Logout {
                break;
            }

            line.clear();
        }

        Ok(())
    }

    /// Process IMAP command
    async fn process_imap_command(
        &self,
        command: &str,
        session: &mut ImapSession,
    ) -> Result<Vec<String>> {
        let parts: Vec<&str> = command.split_whitespace().collect();
        if parts.len() < 2 {
            return Ok(vec!["* BAD Syntax error\r\n".to_string()]);
        }

        let tag = parts[0];
        let cmd = parts[1].to_uppercase();

        match cmd.as_str() {
            "CAPABILITY" => {
                let mut responses = vec![
                    "* CAPABILITY IMAP4rev1 IDLE AUTH=PLAIN AUTH=LOGIN UIDPLUS\r\n".to_string(),
                ];
                responses.push(format!("{tag} OK CAPABILITY completed\r\n"));
                Ok(responses)
            }
            "LOGIN" => {
                if parts.len() < 4 {
                    return Ok(vec![format!(
                        "{} BAD LOGIN requires username and password\r\n",
                        tag
                    )]);
                }

                let username = parts[2].trim_matches('"');
                let password = parts[3].trim_matches('"');
                let surface = "email/imap-login";
                let now = Utc::now();

                // A locked username or source reads exactly like a wrong password, and the
                // password is not checked (hardening P7).
                let Some(attempt) =
                    self.security
                        .begin_login(surface, username, &session.source, now)
                else {
                    return Ok(vec![format!("{} NO LOGIN failed\r\n", tag)]);
                };
                match self.auth_handler.authenticate(username, password) {
                    Ok(true) => {
                        session.state = ImapState::Authenticated;
                        session.authenticated_user = Some(username.to_string());
                        Ok(vec![format!("{} OK LOGIN completed\r\n", tag)])
                    }
                    Ok(false) => {
                        // Recorded first, then answered after the delay.
                        let hold = attempt.failed(now);
                        tokio::time::sleep(hold).await;
                        Ok(vec![format!("{} NO LOGIN failed\r\n", tag)])
                    }
                    Err(_) => Ok(vec![format!("{} NO LOGIN failed\r\n", tag)]),
                }
            }
            "LIST" => {
                if session.state == ImapState::NotAuthenticated {
                    return Ok(vec![format!("{} NO Not authenticated\r\n", tag)]);
                }

                let mut responses = vec!["* LIST () \"/\" \"INBOX\"\r\n".to_string()];
                responses.push(format!("{tag} OK LIST completed\r\n"));
                Ok(responses)
            }
            "SELECT" => {
                if session.state == ImapState::NotAuthenticated {
                    return Ok(vec![format!("{} NO Not authenticated\r\n", tag)]);
                }

                if parts.len() < 3 {
                    return Ok(vec![format!(
                        "{} BAD SELECT requires mailbox name\r\n",
                        tag
                    )]);
                }

                let mailbox = parts[2].trim_matches('"');

                // Get message count for this user
                let message_count = {
                    let store = self.message_store.lock().unwrap();
                    if let Some(user) = &session.authenticated_user {
                        store.get(user).map(|msgs| msgs.len()).unwrap_or(0)
                    } else {
                        0
                    }
                };

                session.state = ImapState::Selected;
                session.selected_mailbox = Some(mailbox.to_string());

                let mut responses = vec![
                    format!("* {} EXISTS\r\n", message_count),
                    "* 0 RECENT\r\n".to_string(),
                    "* OK [UIDVALIDITY 1] UIDs valid\r\n".to_string(),
                    // The store is append-only, so a message's UID is its sequence number and the
                    // next UID is one past the last.
                    format!(
                        "* OK [UIDNEXT {}] Predicted next UID\r\n",
                        message_count + 1
                    ),
                    "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n".to_string(),
                    "* OK [PERMANENTFLAGS (\\Deleted \\Seen \\*)] Limited\r\n".to_string(),
                ];
                responses.push(format!("{tag} OK [READ-WRITE] SELECT completed\r\n"));
                Ok(responses)
            }
            "FETCH" | "UID" => {
                if session.state != ImapState::Selected {
                    return Ok(vec![format!("{} NO Not in selected state\r\n", tag)]);
                }

                // `UID FETCH <set> <items>` carries its sub-command first. UIDs are sequence numbers
                // here (append-only store), so the two forms differ only in what the reply names.
                let by_uid = cmd == "UID";
                let args: &[&str] = if by_uid {
                    if !parts
                        .get(2)
                        .is_some_and(|p| p.eq_ignore_ascii_case("FETCH"))
                    {
                        return Ok(vec![format!("{tag} BAD UID supports only FETCH\r\n")]);
                    }
                    &parts[3..]
                } else {
                    &parts[2..]
                };
                if args.len() < 2 {
                    return Ok(vec![format!(
                        "{} BAD FETCH requires sequence set and items\r\n",
                        tag
                    )]);
                }

                let sequence_set = args[0];
                let items = args[1..].join(" ");
                let with_uid = by_uid || items.to_uppercase().contains("UID");

                // Get messages for this user
                let messages = {
                    let store = self.message_store.lock().unwrap();
                    if let Some(user) = &session.authenticated_user {
                        store.get(user).cloned().unwrap_or_default()
                    } else {
                        Vec::new()
                    }
                };

                let mut responses = Vec::new();
                let seq_nums = expand_set(sequence_set, messages.len());

                for seq_num in seq_nums {
                    if let Some(message) = messages.get(seq_num - 1) {
                        let uid = if with_uid {
                            format!("UID {seq_num} ")
                        } else {
                            String::new()
                        };
                        if items.contains("RFC822") || items.contains("BODY[]") {
                            let email_content = self.format_as_email(message)?;
                            // IMAP literal syntax (RFC 3501 §9): after the declared byte count,
                            // the response's syntax continues immediately -- no CRLF belongs
                            // between the literal's last byte and the closing `)`. A previous
                            // version pushed `email_content + "\r\n"` as its own response before
                            // `)\r\n`, adding two bytes the declared `{len}` did not count; a
                            // strict client (this task's `async-imap`) reads exactly `len` bytes
                            // of literal and then finds a stray `\r\n` where `)` must be, which
                            // fails to parse.
                            self.fetched
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            responses.push(format!(
                                "* {} FETCH ({}RFC822 {{{}}}\r\n{}",
                                seq_num,
                                uid,
                                email_content.len(),
                                email_content
                            ));
                            responses.push(")\r\n".to_string());
                        } else if items.contains("FLAGS") {
                            responses.push(format!("* {seq_num} FETCH ({uid}FLAGS ())\r\n"));
                        } else if with_uid {
                            responses.push(format!("* {seq_num} FETCH (UID {seq_num})\r\n"));
                        }
                    }
                }

                responses.push(format!(
                    "{tag} OK {} completed\r\n",
                    if by_uid { "UID FETCH" } else { "FETCH" }
                ));
                Ok(responses)
            }
            "IDLE" => {
                if session.state != ImapState::Selected {
                    return Ok(vec![format!("{} NO Not in selected state\r\n", tag)]);
                }

                if !self.config.enable_idle {
                    return Ok(vec![format!("{} NO IDLE not supported\r\n", tag)]);
                }

                session.idle_mode = true;
                Ok(vec!["+ idling\r\n".to_string()])
            }
            "DONE" => {
                if session.idle_mode {
                    session.idle_mode = false;
                    Ok(vec![format!("{} OK IDLE terminated\r\n", tag)])
                } else {
                    Ok(vec![format!("{} BAD Not in IDLE\r\n", tag)])
                }
            }
            "LOGOUT" => {
                session.state = ImapState::Logout;
                let mut responses = vec!["* BYE EMRP IMAP Server logging out\r\n".to_string()];
                responses.push(format!("{tag} OK LOGOUT completed\r\n"));
                Ok(responses)
            }
            _ => Ok(vec![format!("{} BAD Command not recognized\r\n", tag)]),
        }
    }

    /// Format `message` as the RFC822 body a `FETCH ... RFC822`/`BODY[]` response carries. Carries
    /// the whole `SecureMessage` as JSON in the body, exactly as a peer's own SMTP DATA body does
    /// (`email_unified.rs`'s `send_message`, `smtp_server.rs`'s `store_message`) -- never
    /// hand-picked fields, per the Global Constraints (spec §4). A previous version reconstructed
    /// a lossy, human-readable envelope from only `from_global_id`/`to_global_id`/`timestamp`/
    /// `encrypted_content`, dropping `sender_proof`, `metadata`, `routing_path` and
    /// `protocol_version` entirely -- unusable by an IMAP-polling receiver that needs the whole
    /// `SecureMessage` back (`email_unified.rs`'s `poll_imap_inbox`).
    /// Errors rather than silently producing a truncated/empty body: the same failure mode as
    /// the wire-format bug this function used to have (a message reaching the wire with content
    /// missing and nothing saying so), by a different mechanism -- a serialize failure here must
    /// not become an empty body a client reads as an empty, successfully-delivered message.
    fn format_as_email(&self, message: &SecureMessage) -> Result<String> {
        let json = serde_json::to_vec(message).map_err(|e| {
            SynapseError::InvalidMessageFormat(format!(
                "failed to serialize SecureMessage for IMAP delivery: {e}"
            ))
        })?;
        Ok(format!(
            "From: {}\r\nTo: {}\r\nSubject: Synapse\r\n\r\n{}",
            message.from_global_id,
            message.to_global_id,
            String::from_utf8_lossy(&json)
        ))
    }
}

/// A message-number set (`5`, `2:4`, `7:*`, `1,3:5`) as the sequence numbers it names in a mailbox of
/// `max` messages, ascending. `*` is the largest number, so `n:*` with `n` past the end names the last
/// message, as real servers answer (RFC 3501 §6.4.8); a client asking for "everything after `n`"
/// must drop what it already has.
fn expand_set(set: &str, max: usize) -> Vec<usize> {
    let number = |text: &str| -> Option<usize> {
        if text == "*" {
            Some(max)
        } else {
            text.parse().ok()
        }
    };
    let mut out = Vec::new();
    for part in set.split(',') {
        let (lo, hi) = match part.split_once(':') {
            Some((a, b)) => (number(a), number(b)),
            None => (number(part), number(part)),
        };
        let (Some(lo), Some(hi)) = (lo, hi) else {
            continue;
        };
        let (lo, hi) = (lo.min(hi), lo.max(hi));
        for n in lo.max(1)..=hi.min(max) {
            if !out.contains(&n) {
                out.push(n);
            }
        }
    }
    out.sort_unstable();
    out
}

impl Clone for SynapseImapServer {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            message_store: Arc::clone(&self.message_store),
            clients: Arc::clone(&self.clients),
            auth_handler: Arc::clone(&self.auth_handler),
            security: self.security.clone(),
            fetched: Arc::clone(&self.fetched),
        }
    }
}
