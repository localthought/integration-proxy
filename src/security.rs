use std::{collections::HashSet, sync::Arc};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use rand::RngCore;
use tokio_postgres::Client;

pub struct OAuthState {
    pub provider: String,
    pub redirect_uri: String,
    pub tenant_id: String,
    pub user_id: String,
    pub verifier: String,
    pub context: Option<String>,
}

#[derive(Clone)]
pub struct Security {
    database: Arc<Client>,
    encryption_key: [u8; 32],
    revoked_subjects: HashSet<String>,
}

impl Security {
    pub async fn connect(
        database_url: &str,
        encryption_key: &str,
        revoked_subjects: Vec<String>,
    ) -> Result<Self, String> {
        let key = URL_SAFE_NO_PAD
            .decode(encryption_key)
            .map_err(|_| "ENCRYPTION_KEY must be base64url")?;
        let encryption_key: [u8; 32] = key
            .try_into()
            .map_err(|_| "ENCRYPTION_KEY must decode to exactly 32 bytes")?;
        let tls = native_tls::TlsConnector::new().map_err(|e| e.to_string())?;
        let tls = postgres_native_tls::MakeTlsConnector::new(tls);
        let (database, connection) = tokio_postgres::connect(database_url, tls)
            .await
            .map_err(|e| e.to_string())?;
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::error!(%error, "postgres connection failed");
            }
        });
        database.batch_execute("CREATE TABLE IF NOT EXISTS used_challenges (nonce TEXT PRIMARY KEY, expires_at TIMESTAMPTZ NOT NULL)").await.map_err(|e| e.to_string())?;
        database.batch_execute("CREATE TABLE IF NOT EXISTS oauth_states (state TEXT PRIMARY KEY, provider TEXT NOT NULL, redirect_uri TEXT NOT NULL, tenant_id TEXT NOT NULL, user_id TEXT NOT NULL, verifier TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL); CREATE TABLE IF NOT EXISTS connection_codes (code TEXT PRIMARY KEY, envelope TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL)").await.map_err(|e| e.to_string())?;
        database.batch_execute("ALTER TABLE oauth_states ADD COLUMN IF NOT EXISTS context TEXT; CREATE TABLE IF NOT EXISTS connection_handoffs (code TEXT PRIMARY KEY, challenge TEXT NOT NULL, envelope TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL)").await.map_err(|e| e.to_string())?;
        Ok(Self {
            database: Arc::new(database),
            encryption_key,
            revoked_subjects: revoked_subjects.into_iter().collect(),
        })
    }

    pub fn is_revoked(&self, tenant_id: &str, user_id: &str) -> bool {
        self.revoked_subjects.contains(tenant_id) || self.revoked_subjects.contains(user_id)
    }

    /// Atomically records a nonce. A duplicate nonce is a replay.
    pub async fn consume_nonce(&self, nonce: &str) -> Result<bool, String> {
        self.database
            .execute("DELETE FROM used_challenges WHERE expires_at <= NOW()", &[])
            .await
            .map_err(|e| e.to_string())?;
        let rows = self.database.execute("INSERT INTO used_challenges (nonce, expires_at) VALUES ($1, NOW() + INTERVAL '10 minutes') ON CONFLICT DO NOTHING", &[&nonce]).await.map_err(|e| e.to_string())?;
        Ok(rows == 1)
    }

    #[allow(dead_code)] // consumed by the OAuth credential flow added after provider registration
    pub fn seal(&self, plaintext: &[u8], associated_data: &[u8]) -> Result<String, String> {
        let cipher = XChaCha20Poly1305::new((&self.encryption_key).into());
        let mut nonce = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: associated_data,
                },
            )
            .map_err(|_| "encryption failed")?;
        Ok(format!(
            "v1.{}.{}",
            URL_SAFE_NO_PAD.encode(nonce),
            URL_SAFE_NO_PAD.encode(ciphertext)
        ))
    }

    #[allow(dead_code)] // consumed by the OAuth credential flow added after provider registration
    pub fn open(&self, envelope: &str, associated_data: &[u8]) -> Option<Vec<u8>> {
        let (version, value) = envelope.split_once('.')?;
        if version != "v1" {
            return None;
        }
        let (nonce, ciphertext) = value.split_once('.')?;
        let nonce = URL_SAFE_NO_PAD.decode(nonce).ok()?;
        let ciphertext = URL_SAFE_NO_PAD.decode(ciphertext).ok()?;
        if nonce.len() != 24 {
            return None;
        }
        XChaCha20Poly1305::new((&self.encryption_key).into())
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: associated_data,
                },
            )
            .ok()
    }

    pub async fn store_oauth_state(&self, state: &str, value: &OAuthState) -> Result<(), String> {
        self.database.execute("INSERT INTO oauth_states (state, provider, redirect_uri, tenant_id, user_id, verifier, context, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,NOW() + INTERVAL '10 minutes')", &[&state, &value.provider, &value.redirect_uri, &value.tenant_id, &value.user_id, &value.verifier, &value.context]).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn take_oauth_state(&self, state: &str) -> Result<Option<OAuthState>, String> {
        let row = self.database.query_opt("DELETE FROM oauth_states WHERE state = $1 AND expires_at > NOW() RETURNING provider, redirect_uri, tenant_id, user_id, verifier, context", &[&state]).await.map_err(|e| e.to_string())?;
        Ok(row.map(|r| OAuthState {
            provider: r.get(0),
            redirect_uri: r.get(1),
            tenant_id: r.get(2),
            user_id: r.get(3),
            verifier: r.get(4),
            context: r.get(5),
        }))
    }

    pub async fn store_handoff(
        &self,
        code: &str,
        challenge: &str,
        envelope: &str,
    ) -> Result<(), String> {
        self.database
            .execute(
                "DELETE FROM connection_handoffs WHERE expires_at <= NOW()",
                &[],
            )
            .await
            .map_err(|e| e.to_string())?;
        self.database.execute("INSERT INTO connection_handoffs (code, challenge, envelope, expires_at) VALUES ($1,$2,$3,NOW() + INTERVAL '5 minutes')", &[&code, &challenge, &envelope]).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Validate PKCE and consume atomically; a wrong verifier cannot burn a valid code.
    pub async fn take_handoff(
        &self,
        code: &str,
        challenge: &str,
    ) -> Result<Option<String>, String> {
        self.database.query_opt("DELETE FROM connection_handoffs WHERE code = $1 AND challenge = $2 AND expires_at > NOW() RETURNING envelope", &[&code, &challenge]).await.map_err(|e| e.to_string()).map(|row| row.map(|r| r.get(0)))
    }

    pub async fn store_connection_code(&self, code: &str, envelope: &str) -> Result<(), String> {
        self.database.execute("INSERT INTO connection_codes (code, envelope, expires_at) VALUES ($1,$2,NOW() + INTERVAL '5 minutes')", &[&code, &envelope]).await.map_err(|e| e.to_string())?;
        Ok(())
    }

    pub async fn take_connection_code(&self, code: &str) -> Result<Option<String>, String> {
        self.database.query_opt("DELETE FROM connection_codes WHERE code = $1 AND expires_at > NOW() RETURNING envelope", &[&code]).await.map_err(|e| e.to_string()).map(|row| row.map(|r| r.get(0)))
    }
}
