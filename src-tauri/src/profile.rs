//! Durable profile persistence for the Shadowgram shell.

use base64::prelude::*;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const PROFILE_FILE: &str = "profile.json";
const DIAGNOSTIC_LIMIT: usize = 200;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileData {
    pub installation_id: String,
    pub profile_label: String,
    pub identity: Option<StoredIdentity>,
    pub contacts: Vec<StoredContact>,
    pub chats: Vec<StoredChat>,
    pub messages: HashMap<String, Vec<StoredMessage>>,
    pub diagnostics: Vec<DiagnosticEntry>,
    pub created_at: u64,
    pub updated_at: u64,
}

impl Default for ProfileData {
    fn default() -> Self {
        let timestamp = now();
        Self {
            installation_id: format!("install-{}", now_nanos()),
            profile_label: std::env::var("SHADOWGRAM_PROFILE")
                .unwrap_or_else(|_| "default".to_string()),
            identity: None,
            contacts: Vec::new(),
            chats: Vec::new(),
            messages: HashMap::new(),
            diagnostics: vec![DiagnosticEntry::info(
                "profile.initialized",
                "Created empty durable profile".to_string(),
            )],
            created_at: timestamp,
            updated_at: timestamp,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredIdentity {
    pub fingerprint: String,
    pub fingerprint_full: String,
    pub public_key_base64: String,
    pub secret_key_base64: String,
    pub invite_payload: String,
    pub generation: u32,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredContact {
    pub id: String,
    pub fingerprint: String,
    pub alias: String,
    pub status: String,
    pub public_key_base64: Option<String>,
    pub invite_payload: String,
    pub endpoint: Option<ContactEndpoint>,
    pub previous_fingerprints: Vec<String>,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactEndpoint {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredChat {
    pub id: String,
    pub contact_fingerprint: String,
    pub created_at: u64,
    pub immutable_history: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMessage {
    pub id: String,
    pub content: String,
    pub direction: String,
    pub timestamp: u64,
    pub status: String,
    pub error: Option<String>,
    pub destination_fingerprint: String,
    pub immutable: bool,
    pub delivered_at: Option<u64>,
    pub retry_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticEntry {
    pub level: String,
    pub stage: String,
    pub message: String,
    pub timestamp: u64,
}

impl DiagnosticEntry {
    pub fn info(stage: &str, message: String) -> Self {
        Self {
            level: "info".to_string(),
            stage: stage.to_string(),
            message,
            timestamp: now(),
        }
    }

    pub fn warn(stage: &str, message: String) -> Self {
        Self {
            level: "warn".to_string(),
            stage: stage.to_string(),
            message,
            timestamp: now(),
        }
    }

}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvitePayload {
    pub version: u8,
    pub fingerprint: String,
    pub public_key_base64: String,
    pub endpoint: Option<ContactEndpoint>,
}

pub struct ProfileStore {
    path: PathBuf,
    data: ProfileData,
}

impl ProfileStore {
    pub fn load_or_init(profile_dir: PathBuf) -> Result<Self, String> {
        fs::create_dir_all(&profile_dir).map_err(|e| e.to_string())?;
        let path = profile_dir.join(PROFILE_FILE);

        if path.exists() {
            let raw = fs::read_to_string(&path).map_err(|e| e.to_string())?;
            let mut data: ProfileData = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
            data.diagnostics.push(DiagnosticEntry::info(
                "profile.load",
                format!("Loaded profile from {}", path.display()),
            ));
            trim_diagnostics(&mut data.diagnostics);
            return Ok(Self { path, data });
        }

        let mut store = Self {
            path,
            data: ProfileData::default(),
        };
        store.save()?;
        Ok(store)
    }

    pub fn data(&self) -> &ProfileData {
        &self.data
    }

    pub fn data_mut(&mut self) -> &mut ProfileData {
        &mut self.data
    }

    pub fn save(&mut self) -> Result<(), String> {
        self.data.updated_at = now();
        trim_diagnostics(&mut self.data.diagnostics);
        let serialized = serde_json::to_string_pretty(&self.data).map_err(|e| e.to_string())?;
        let temp_path = self.path.with_extension("json.tmp");
        fs::write(&temp_path, serialized).map_err(|e| e.to_string())?;
        fs::rename(&temp_path, &self.path).map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn ensure_identity(
        &mut self,
        endpoint: Option<ContactEndpoint>,
    ) -> Result<StoredIdentity, String> {
        if let Some(identity) = self.data.identity.as_ref() {
            let existing = identity.clone();
            self.push_diag(DiagnosticEntry::info(
                "identity.loaded",
                format!("Reused stable fingerprint {}", existing.fingerprint),
            ));
            return Ok(existing);
        }

        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        let public_key = verifying_key.to_bytes();
        let secret_key = signing_key.to_bytes();
        let fingerprint_full = hex::encode(Sha256::digest(public_key));
        let fingerprint = format_fingerprint(&fingerprint_full);
        let invite = InvitePayload {
            version: 1,
            fingerprint: fingerprint.clone(),
            public_key_base64: BASE64_STANDARD.encode(public_key),
            endpoint,
        };
        let identity = StoredIdentity {
            fingerprint,
            fingerprint_full,
            public_key_base64: invite.public_key_base64.clone(),
            secret_key_base64: BASE64_STANDARD.encode(secret_key),
            invite_payload: invite_to_string(&invite)?,
            generation: 1,
            created_at: now(),
            updated_at: now(),
        };
        self.data.identity = Some(identity.clone());
        self.push_diag(DiagnosticEntry::info(
            "identity.created",
            format!(
                "Generated new persistent fingerprint {}",
                identity.fingerprint
            ),
        ));
        self.save()?;
        Ok(identity)
    }

    pub fn update_identity_endpoint(
        &mut self,
        endpoint: Option<ContactEndpoint>,
    ) -> Result<(), String> {
        if let Some(identity) = self.data.identity.as_mut() {
            let invite = InvitePayload {
                version: 1,
                fingerprint: identity.fingerprint.clone(),
                public_key_base64: identity.public_key_base64.clone(),
                endpoint,
            };
            identity.invite_payload = invite_to_string(&invite)?;
            identity.updated_at = now();
            self.save()?;
        }
        Ok(())
    }

    pub fn reset_identity(&mut self) -> Result<(), String> {
        let timestamp = now();
        self.data = ProfileData {
            created_at: timestamp,
            updated_at: timestamp,
            ..ProfileData::default()
        };
        self.push_diag(DiagnosticEntry::warn(
            "profile.reset",
            "Identity and local state were securely reset from the app perspective".to_string(),
        ));
        self.save()
    }

    pub fn upsert_contact(
        &mut self,
        alias: String,
        invite_payload: String,
        parsed: InvitePayload,
    ) -> Result<StoredContact, String> {
        if let Some(identity) = self.data.identity.as_ref() {
            if identity.fingerprint == parsed.fingerprint {
                return Err("You cannot add your own fingerprint as a contact".to_string());
            }
        }

        if let Some(existing) = self
            .data
            .contacts
            .iter_mut()
            .find(|contact| contact.fingerprint == parsed.fingerprint)
        {
            existing.alias = alias;
            existing.status = if parsed.endpoint.is_some() {
                "reachable".to_string()
            } else {
                "unreachable".to_string()
            };
            existing.public_key_base64 = Some(parsed.public_key_base64);
            existing.invite_payload = invite_payload;
            existing.endpoint = parsed.endpoint;
            existing.updated_at = now();
            let contact = existing.clone();
            self.push_diag(DiagnosticEntry::info(
                "contact.updated",
                format!("Updated contact {}", contact.fingerprint),
            ));
            self.save()?;
            return Ok(contact);
        }

        let contact = StoredContact {
            id: format!("contact-{}", now_nanos()),
            fingerprint: parsed.fingerprint.clone(),
            alias,
            status: if parsed.endpoint.is_some() {
                "reachable".to_string()
            } else {
                "unreachable".to_string()
            },
            public_key_base64: Some(parsed.public_key_base64),
            invite_payload,
            endpoint: parsed.endpoint,
            previous_fingerprints: Vec::new(),
            updated_at: now(),
        };
        self.data.contacts.push(contact.clone());
        self.push_diag(DiagnosticEntry::info(
            "contact.added",
            format!("Imported contact {}", contact.fingerprint),
        ));
        self.save()?;
        Ok(contact)
    }

    pub fn create_chat(&mut self, contact_fingerprint: &str) -> Result<StoredChat, String> {
        if !self
            .data
            .contacts
            .iter()
            .any(|contact| contact.fingerprint == contact_fingerprint)
        {
            return Err("Contact not found".to_string());
        }

        if let Some(existing) = self
            .data
            .chats
            .iter()
            .find(|chat| chat.contact_fingerprint == contact_fingerprint)
        {
            return Ok(existing.clone());
        }

        let chat = StoredChat {
            id: format!("chat-{}", now_nanos()),
            contact_fingerprint: contact_fingerprint.to_string(),
            created_at: now(),
            immutable_history: true,
        };
        self.data.chats.push(chat.clone());
        self.push_diag(DiagnosticEntry::info(
            "chat.created",
            format!("Created durable chat for {}", contact_fingerprint),
        ));
        self.save()?;
        Ok(chat)
    }

    pub fn append_message(&mut self, chat_id: &str, message: StoredMessage) -> Result<(), String> {
        self.data
            .messages
            .entry(chat_id.to_string())
            .or_default()
            .push(message);
        self.save()
    }

    pub fn update_message_status(
        &mut self,
        chat_id: &str,
        message_id: &str,
        status: String,
        error: Option<String>,
        delivered_at: Option<u64>,
        retry_count: u32,
    ) -> Result<(), String> {
        let Some(messages) = self.data.messages.get_mut(chat_id) else {
            return Ok(());
        };
        if let Some(message) = messages.iter_mut().find(|message| message.id == message_id) {
            message.status = status;
            message.error = error;
            message.delivered_at = delivered_at;
            message.retry_count = retry_count;
        }
        self.save()
    }

    pub fn messages_for_chat(&self, chat_id: &str) -> Vec<StoredMessage> {
        self.data.messages.get(chat_id).cloned().unwrap_or_default()
    }

    pub fn pending_outbound(&self) -> Vec<(String, StoredMessage)> {
        self.data
            .messages
            .iter()
            .flat_map(|(chat_id, messages)| {
                messages
                    .iter()
                    .filter(|message| {
                        message.direction == "outgoing"
                            && (message.status == "queued" || message.status == "failed")
                    })
                    .cloned()
                    .map(|message| (chat_id.clone(), message))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    pub fn push_diag(&mut self, entry: DiagnosticEntry) {
        self.data.diagnostics.push(entry);
        trim_diagnostics(&mut self.data.diagnostics);
    }

    pub fn diagnostics(&self) -> Vec<DiagnosticEntry> {
        self.data.diagnostics.clone()
    }
}

pub fn parse_invite(input: &str) -> Result<InvitePayload, String> {
    let value = input.trim();
    if value.starts_with("shadowgram://invite/") {
        let encoded = value.trim_start_matches("shadowgram://invite/");
        let decoded = BASE64_STANDARD.decode(encoded).map_err(|e| e.to_string())?;
        return serde_json::from_slice(&decoded).map_err(|e| e.to_string());
    }

    if value.starts_with('{') {
        return serde_json::from_str(value).map_err(|e| e.to_string());
    }

    Ok(InvitePayload {
        version: 1,
        fingerprint: value.to_string(),
        public_key_base64: String::new(),
        endpoint: None,
    })
}

pub fn invite_to_string(invite: &InvitePayload) -> Result<String, String> {
    let raw = serde_json::to_vec(invite).map_err(|e| e.to_string())?;
    Ok(format!(
        "shadowgram://invite/{}",
        BASE64_STANDARD.encode(raw)
    ))
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}

fn trim_diagnostics(diagnostics: &mut Vec<DiagnosticEntry>) {
    if diagnostics.len() > DIAGNOSTIC_LIMIT {
        let remove = diagnostics.len() - DIAGNOSTIC_LIMIT;
        diagnostics.drain(0..remove);
    }
}

fn format_fingerprint(full_hex: &str) -> String {
    full_hex
        .chars()
        .take(24)
        .collect::<Vec<_>>()
        .chunks(6)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_profile() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("shadowgram-test-{}", now_nanos()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn loads_same_identity_across_restarts() {
        let dir = temp_profile();

        let fingerprint = {
            let mut store = ProfileStore::load_or_init(dir.clone()).unwrap();
            store.ensure_identity(None).unwrap().fingerprint
        };

        let mut store = ProfileStore::load_or_init(dir).unwrap();
        let again = store.ensure_identity(None).unwrap();
        assert_eq!(fingerprint, again.fingerprint);
    }

    #[test]
    fn reset_creates_new_identity_after_restart() {
        let dir = temp_profile();
        let first = {
            let mut store = ProfileStore::load_or_init(dir.clone()).unwrap();
            store.ensure_identity(None).unwrap().fingerprint
        };
        {
            let mut store = ProfileStore::load_or_init(dir.clone()).unwrap();
            store.reset_identity().unwrap();
            store.ensure_identity(None).unwrap();
        }
        let mut store = ProfileStore::load_or_init(dir).unwrap();
        let second = store.ensure_identity(None).unwrap().fingerprint;
        assert_ne!(first, second);
    }

    #[test]
    fn invite_roundtrip_works() {
        let invite = InvitePayload {
            version: 1,
            fingerprint: "abcd".to_string(),
            public_key_base64: "pub".to_string(),
            endpoint: Some(ContactEndpoint {
                host: "127.0.0.1".to_string(),
                port: 41000,
            }),
        };
        let encoded = invite_to_string(&invite).unwrap();
        let decoded = parse_invite(&encoded).unwrap();
        assert_eq!(decoded.fingerprint, invite.fingerprint);
        assert_eq!(decoded.endpoint.unwrap().port, 41000);
    }
}
