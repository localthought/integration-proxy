use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Deterministically derives a per-tenant secret from the server secret
/// and a stable tenant identity.
///
/// The secret is self-describing: it encodes the identity alongside an HMAC
/// over it, so [`verify`] can check a presented secret is genuine without
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

/// Verifies a secret produced by [`derive`], returning the embedded identity
/// if the signature checks out.
pub fn verify(server_secret: &str, secret: &str) -> Option<String> {
    let (identity_b64, _) = secret.split_once('.')?;
    let identity_bytes = URL_SAFE_NO_PAD.decode(identity_b64).ok()?;
    let identity = String::from_utf8(identity_bytes).ok()?;

    let expected = derive(server_secret, &identity);
    if constant_time_eq(expected.as_bytes(), secret.as_bytes()) {
        Some(identity)
    } else {
        None
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
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

    #[test]
    fn verify_accepts_a_genuine_secret() {
        let secret = derive("server-secret", "user@example.com");
        assert_eq!(
            verify("server-secret", &secret),
            Some("user@example.com".to_string())
        );
    }

    #[test]
    fn verify_rejects_a_tampered_signature() {
        let mut secret = derive("server-secret", "user@example.com");
        secret.push('x');
        assert_eq!(verify("server-secret", &secret), None);
    }

    #[test]
    fn verify_rejects_the_wrong_server_secret() {
        let secret = derive("server-secret", "user@example.com");
        assert_eq!(verify("a-different-secret", &secret), None);
    }

    #[test]
    fn verify_rejects_garbage_input() {
        assert_eq!(verify("server-secret", "not-a-valid-secret"), None);
        assert_eq!(verify("server-secret", ""), None);
    }

    #[test]
    fn verify_rejects_an_identity_substituted_from_another_secret() {
        // An attacker can't just swap in a different (base64-encoded)
        // identity next to a signature they don't control.
        let victim = derive("server-secret", "victim@example.com");
        let (_, victim_signature) = victim.split_once('.').unwrap();
        let forged = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(b"attacker@example.com"),
            victim_signature
        );
        assert_eq!(verify("server-secret", &forged), None);
    }
}
