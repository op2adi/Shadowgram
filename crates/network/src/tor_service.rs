//! Tor onion-service hosting for Shadowgram.
//!
//! Each Shadowgram instance runs a persistent v3 onion service.  The service
//! identity key is kept in Arti's native keystore under a fixed nickname, so
//! the `.onion` address survives restarts as long as the `state_dir` stays the
//! same.  Incoming connections are translated into `tokio::io` streams by the
//! `handle_rend_requests` helper.

use arti_client::{config::TorClientConfigBuilder, TorClient, TorClientConfig};
use futures::StreamExt;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tor_hsservice::{
    handle_rend_requests, HsNickname, OnionServiceConfig, RendRequest, RunningOnionService,
    StreamRequest,
};
use tor_rtcompat::PreferredRuntime;

/// Errors from the onion-service layer.
#[derive(Debug, Error)]
pub enum OnionServiceError {
    #[error("Arti bootstrap failed: {0}")]
    Bootstrap(String),

    #[error("Failed to launch onion service: {0}")]
    Launch(String),

    #[error("Onion address not yet available (descriptor not yet published)")]
    AddressNotReady,

    #[error("Tor connect failed: {0}")]
    Connect(String),

    #[error("Invalid onion nickname: {0}")]
    InvalidNickname(String),
}

/// Port that each Shadowgram peer listens on inside its own onion service.
pub const ONION_PORT: u16 = 7373;

/// Fixed service nickname — determines which keystore slot holds our HsId key.
const SG_NICKNAME: &str = "shadowgram";

/// A running Shadowgram Tor node: Arti client + active onion service.
///
/// Clone is cheap (all fields are `Arc`-backed).
/// Note: `create_bootstrapped` already returns `Arc<TorClient>`, so `client`
/// is `Arc<TorClient<PreferredRuntime>>` directly.
#[derive(Clone)]
pub struct ShadowgramTor {
    client: Arc<TorClient<PreferredRuntime>>,
    svc: Arc<RunningOnionService>,
}

impl ShadowgramTor {
    /// Bootstrap Arti with `state_dir` as the persistent storage root and
    /// launch our onion service.  The `state_dir` must survive restarts so
    /// the `.onion` address stays stable.
    pub async fn start(state_dir: &Path) -> Result<(Self, impl futures::Stream<Item = StreamRequest> + Unpin), OnionServiceError> {
        // Build Arti config with our state dir.
        // from_directories is on TorClientConfigBuilder; build() produces TorClientConfig.
        let cfg = TorClientConfigBuilder::from_directories(
            state_dir.join("arti-state"),
            state_dir.join("arti-cache"),
        )
        .build()
        .map_err(|e| OnionServiceError::Bootstrap(e.to_string()))?;

        // create_bootstrapped returns Arc<TorClient>; no extra Arc::new() needed.
        let client = TorClient::create_bootstrapped(cfg)
            .await
            .map_err(|e| OnionServiceError::Bootstrap(e.to_string()))?;

        let nickname = HsNickname::new(SG_NICKNAME.to_string())
            .map_err(|e| OnionServiceError::InvalidNickname(e.to_string()))?;

        let svc_config = OnionServiceConfig::builder()
            .nickname(nickname)
            .build()
            .map_err(|e| OnionServiceError::Launch(e.to_string()))?;

        let (svc, rend_stream) = client
            .launch_onion_service(svc_config)
            .map_err(|e| OnionServiceError::Launch(e.to_string()))?
            .ok_or_else(|| OnionServiceError::Launch("service disabled in config".into()))?;

        let stream_requests = handle_rend_requests(rend_stream).boxed();

        Ok((Self { client, svc }, stream_requests))
    }

    /// Return the `.onion` address (without port) once Arti has published the
    /// descriptor.  Returns `None` if the key is not yet available.
    pub fn onion_address(&self) -> Option<String> {
        use safelog::DisplayRedacted as _;
        self.svc
            .onion_address()
            .map(|id| id.display_unredacted().to_string())
    }

    /// Full `<addr>.onion:<port>` string ready to put in an invite.
    pub fn onion_endpoint(&self) -> Option<String> {
        self.onion_address()
            .map(|addr| format!("{}:{}", addr, ONION_PORT))
    }

    /// Dial a peer at `<onion>.onion:<port>` over Tor.
    /// Returns an async stream you can read/write.
    pub async fn connect(&self, onion_endpoint: &str) -> Result<impl AsyncRead + AsyncWrite + Unpin, OnionServiceError> {
        self.client
            .connect(onion_endpoint)
            .await
            .map_err(|e| OnionServiceError::Connect(e.to_string()))
    }

    /// Accept an inbound `StreamRequest` and return the async stream.
    pub async fn accept_stream(
        req: StreamRequest,
    ) -> Result<impl AsyncRead + AsyncWrite + Unpin, OnionServiceError> {
        use tor_cell::relaycell::msg::Connected;
        req.accept(Connected::new_empty())
            .await
            .map_err(|e| OnionServiceError::Connect(e.to_string()))
    }
}
