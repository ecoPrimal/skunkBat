// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2025-2026 ecoPrimal <ecoPrimal@pm.me>

//! skunkBat `UniBin` — single binary, multiple modes.
//!
//! Implements BTSP Phase 1 (socket naming, `FAMILY_ID` guard) and
//! Primal IPC Protocol v3.1 (standalone startup, `--port` + `--bind` convention).
//!
//! Supports `TRANSPORT_ENDPOINT` env var for launcher-injected transport binding
//! (sourDough `TransportEndpoint` standard, Wave 100+).

mod ipc;

use clap::{Parser, Subcommand};
use skunk_bat_core::PrimalLifecycle;
use skunk_bat_core::{SkunkBat, SkunkBatConfig};
use skunk_bat_integrations::TransportEndpoint;
use skunk_bat_integrations::verifier::RuntimeVerifier;
use tracing_subscriber::EnvFilter;

/// Typed error for the server binary — replaces `Box<dyn Error>`.
#[derive(Debug, thiserror::Error)]
enum ServerError {
    #[error("config: {0}")]
    Config(String),

    #[error("{0}")]
    Primal(#[from] skunk_bat_core::PrimalError),

    #[error("{0}")]
    SkunkBat(#[from] skunk_bat_core::SkunkBatError),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialize: {0}")]
    Serialize(#[from] serde_json::Error),

    #[error("{0}")]
    Transport(#[from] ipc::transport::TransportError),
}

fn default_port() -> u16 {
    std::env::var(skunk_bat_core::env_keys::SKUNKBAT_PORT)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(skunk_bat_core::DEFAULT_PORT)
}

fn default_bind() -> String {
    std::env::var(skunk_bat_core::env_keys::SKUNKBAT_LISTEN_ADDR)
        .unwrap_or_else(|_| "127.0.0.1".to_owned())
}

/// Primal bind mode — standard startup contract (Wave 109).
///
/// Determines which transports are active without per-primal flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BindMode {
    UdsOnly,
    TcpOnly,
    Fallback,
}

impl BindMode {
    fn from_env() -> Self {
        std::env::var(skunk_bat_core::env_keys::PRIMAL_BIND_MODE)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(Self::UdsOnly)
    }
}

impl std::fmt::Display for BindMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UdsOnly => f.write_str("uds-only"),
            Self::TcpOnly => f.write_str("tcp-only"),
            Self::Fallback => f.write_str("fallback"),
        }
    }
}

/// Error returned when parsing an unrecognized `PRIMAL_BIND_MODE` value.
#[derive(Debug, thiserror::Error)]
#[error("unknown bind mode: {value} (expected: uds-only, tcp-only, fallback)")]
struct BindModeParseError {
    value: String,
}

impl std::str::FromStr for BindMode {
    type Err = BindModeParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().replace('-', "_").as_str() {
            "uds_only" | "uds" => Ok(Self::UdsOnly),
            "tcp_only" | "tcp" => Ok(Self::TcpOnly),
            "fallback" | "both" => Ok(Self::Fallback),
            _ => Err(BindModeParseError {
                value: s.to_owned(),
            }),
        }
    }
}

fn default_bind_mode() -> BindMode {
    BindMode::from_env()
}

/// skunkBat — Reconnaissance & Automated Defense
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the IPC server (JSON-RPC 2.0, standard primal startup contract).
    Server {
        /// Transport bind mode (standard primal contract).
        ///
        /// - `uds-only` (default): UDS only, zero-port standard.
        /// - `tcp-only`: TCP only (Android/grapheneGate where UDS is denied).
        /// - `fallback`: Both UDS + TCP (debug/standalone).
        ///
        /// Reads from `PRIMAL_BIND_MODE` env var if not passed.
        #[arg(long, default_value_t = default_bind_mode())]
        bind_mode: BindMode,

        /// TCP listen address.
        ///
        /// Override with `SKUNKBAT_LISTEN_ADDR` env var or `--bind`.
        /// Defaults to `127.0.0.1` (localhost-only).
        #[arg(long, default_value_t = default_bind())]
        bind: String,

        /// TCP port (used when bind-mode includes TCP).
        ///
        /// Override with `SKUNKBAT_PORT` env var. Default: 9750.
        #[arg(long, default_value_t = default_port())]
        port: u16,

        /// Explicit UDS socket path (overrides BTSP-derived path).
        ///
        /// Example: `--socket /run/membrane/skunkbat.sock`
        #[arg(long)]
        socket: Option<String>,
    },

    /// One-shot health check (exits 0 if healthy).
    Health,

    /// One-shot network scan (prints JSON to stdout).
    Scan,

    /// One-shot threat detection (prints JSON to stdout).
    Detect,

    /// Run comprehensive health diagnostics (`ecoBin` standard).
    Doctor,
}

#[tokio::main]
async fn main() -> Result<(), ServerError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    if let Err(e) = ipc::transport::BtspConfig::from_env() {
        tracing::error!("{e}");
        std::process::exit(1);
    }

    let cli = Cli::parse();

    match cli.command {
        Commands::Server {
            bind_mode,
            bind,
            port,
            socket,
        } => run_server(bind_mode, &bind, port, socket.as_deref()).await,

        Commands::Health => {
            use skunk_bat_core::PrimalHealth;
            let mut sb = started_instance().await?;
            let v = serde_json::to_value(&sb.health_check().await?)?;
            println!("{}", serde_json::to_string_pretty(&v)?);
            sb.stop().await?;
            Ok(())
        }
        Commands::Scan => {
            let mut sb = started_instance().await?;
            let v = serde_json::to_value(&sb.scan_network().await?)?;
            println!("{}", serde_json::to_string_pretty(&v)?);
            sb.stop().await?;
            Ok(())
        }
        Commands::Detect => {
            let mut sb = started_instance().await?;
            let v = serde_json::to_value(&sb.detect_threats().await?)?;
            println!("{}", serde_json::to_string_pretty(&v)?);
            sb.stop().await?;
            Ok(())
        }
        Commands::Doctor => {
            println!("🏥 skunkBat Health Diagnostics");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!();
            println!("📦 Binary Information");
            println!("   Name: skunkbat");
            println!("   Version: {}", env!("CARGO_PKG_VERSION"));
            println!("   Role: Intrusion Detection & Automated Defense");
            println!();
            println!("🛡️  Security Capabilities");
            println!("   • Network scanning (ARP, port, service)");
            println!("   • Threat detection (anomaly, pattern)");
            println!("   • Health monitoring (one-shot + continuous)");
            println!();
            println!("🔌 Transport");
            println!("   Default bind mode: {}", default_bind_mode());
            println!("   Default bind: {}", default_bind());
            println!("   Default port: {}", default_port());
            println!();
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("✅ Health check complete!");
            Ok(())
        }
    }
}

/// Create and start a `SkunkBat` instance for one-shot commands.
async fn started_instance() -> Result<SkunkBat, ServerError> {
    let config = SkunkBatConfig::from_env();
    let mut skunkbat = SkunkBat::new(config);
    skunkbat.start().await?;
    Ok(skunkbat)
}

async fn run_server(
    mut bind_mode: BindMode,
    bind: &str,
    port: u16,
    socket: Option<&str>,
) -> Result<(), ServerError> {
    // TRANSPORT_ENDPOINT env var: launcher-injected transport (sourDough standard).
    // Overrides bind-mode when set.
    let (socket, bind_mode, port) = match TransportEndpoint::from_env() {
        Some(TransportEndpoint::Uds { ref path }) => {
            tracing::info!("TRANSPORT_ENDPOINT: UDS at {path}");
            (Some(path.clone()), BindMode::UdsOnly, port)
        }
        Some(TransportEndpoint::Tcp {
            ref host,
            port: ep_port,
        }) => {
            tracing::info!("TRANSPORT_ENDPOINT: TCP at {host}:{ep_port}");
            (socket.map(ToOwned::to_owned), BindMode::TcpOnly, ep_port)
        }
        Some(TransportEndpoint::MeshRelay { .. }) => {
            return Err(ServerError::Config(
                "mesh_relay transport not supported for server binding".into(),
            ));
        }
        None => {
            // --port on CLI with uds-only mode implies user wants fallback
            if bind_mode == BindMode::UdsOnly && std::env::args().any(|a| a == "--port") {
                bind_mode = BindMode::Fallback;
            }
            (socket.map(ToOwned::to_owned), bind_mode, port)
        }
    };

    let no_tcp = bind_mode == BindMode::UdsOnly;
    let no_uds = bind_mode == BindMode::TcpOnly;

    let config = SkunkBatConfig::from_env();
    let verifier = RuntimeVerifier::from_env();
    let mut skunkbat = SkunkBat::with_verifier(config, verifier);

    skunkbat.start().await?;

    match bind_mode {
        BindMode::UdsOnly => {
            tracing::info!("skunkBat server starting (bind-mode: uds-only)");
        }
        BindMode::TcpOnly => {
            tracing::info!("skunkBat server starting on {bind}:{port} (bind-mode: tcp-only)");
        }
        BindMode::Fallback => {
            tracing::info!("skunkBat server starting on {bind}:{port} + UDS (bind-mode: fallback)");
        }
    }

    ipc::serve(
        skunkbat,
        bind.to_owned(),
        port,
        socket.as_deref(),
        no_uds,
        no_tcp,
    )
    .await?;
    Ok(())
}
