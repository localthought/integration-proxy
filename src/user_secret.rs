use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Deterministically derives a per-identity secret from the server secret
/// and a stable identity (the Google account's `sub` claim).
///
/// The secret is self-describing: it encodes the identity alongside an HMAC
/// over it, so a verifier can check a presented secret is genuine without
/// any server-side storage, keeping the server stateless.
pub fn derive(server_secret: &str, identity: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(server_secret.as_bytes())
        .expect("HMAC accepts a key of any length");
    mac.update(identity.as_bytes());
    let signature = mac.finalize().into_bytes();

    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(identity.as_bytes()),
        URL_SAFE_NO_PAD.encode(signature)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_deterministic() {
        let a = derive("server-secret", "user@example.com");
        let b = derive("server-secret", "user@example.com");
        assert_eq!(a, b);
    }

    #[test]
    fn derive_differs_per_identity() {
        let a = derive("server-secret", "alice@example.com");
        let b = derive("server-secret", "bob@example.com");
        assert_ne!(a, b);
    }

    #[test]
    fn derive_differs_per_server_secret() {
        let a = derive("server-secret-1", "user@example.com");
        let b = derive("server-secret-2", "user@example.com");
        assert_ne!(a, b);
    }
}
