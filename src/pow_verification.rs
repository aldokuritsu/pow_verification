use sha2::{Sha256, Digest};
use std::time::{SystemTime, UNIX_EPOCH};

// Type alias pour plus de clarté
type HashString = String;

// Durée maximale pour laquelle un hash est considéré valide (anti-spam)
const HASH_VALIDITY_DURATION: u64 = 100; // en secondes

/// Fonction pour calculer le hash à partir du nonce, des données et du timestamp
/// Renvoie une `HashString`.
fn calculate_hash(nonce: u64, data: &str, timestamp: u64) -> HashString {
    let mut hasher = Sha256::new();
    
    // Mise à jour du hasher avec les éléments dans l'ordre : data, timestamp, nonce
    hasher.update(data);
    hasher.update(timestamp.to_string());
    hasher.update(nonce.to_string());

    let result = hasher.finalize();
    format!("{:x}", result)
}

/// Fonction pour vérifier la preuve de travail (PoW)
/// Renvoie `Result<bool, String>` pour indiquer si la vérification a réussi ou échoué avec un message d'erreur.
pub fn verify_pow(nonce: u64, data: &str, timestamp: u64, expected_hash: &str) -> Result<bool, String> {
    let computed_hash = calculate_hash(nonce, data, timestamp);
    
    if computed_hash != expected_hash {
        return Err(format!(
            "La vérification du PoW a échoué.\nExpected: {}\nComputed: {}",
            expected_hash, computed_hash
        ));
    }

    // Vérification du délai d'expiration
    let current_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "Erreur lors de la récupération du timestamp actuel".to_string())?
        .as_secs();

    if current_timestamp > timestamp + HASH_VALIDITY_DURATION {
        return Err(format!(
            "Le hash a expiré ! Expiré de {} secondes.",
            current_timestamp - (timestamp + HASH_VALIDITY_DURATION)
        ));
    }

    Ok(true) // PoW est valide
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH, Duration};

    #[test]
    fn test_pow_verification_success_within_time() {
        let nonce: u64 = 3361;
        let data = "toto";
        let timestamp: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expected_hash = calculate_hash(nonce, data, timestamp);

        // Test que la vérification fonctionne dans le temps imparti
        let result = verify_pow(nonce, data, timestamp, &expected_hash);
        assert!(result.is_ok(), "La vérification aurait dû réussir.");
    }

    #[test]
    fn test_pow_verification_failure_due_to_expiry() {
        let nonce: u64 = 3361;
        let data = "toto";
        let expired_timestamp: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() - (HASH_VALIDITY_DURATION + 1); // Temps dépassé
        let expected_hash = calculate_hash(nonce, data, expired_timestamp);

        // Test que la vérification échoue en raison de l'expiration
        let result = verify_pow(nonce, data, expired_timestamp, &expected_hash);
        assert!(result.is_err(), "La vérification aurait dû échouer en raison de l'expiration.");
        assert_eq!(result.unwrap_err(), "Le hash a expiré ! Expiré de 1 secondes.");
    }

    #[test]
    fn test_pow_verification_failure_due_to_wrong_data() {
        let nonce: u64 = 3361;
        let data = "toto";
        let timestamp: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let wrong_hash = "abcdef1234567890"; // Mauvais hash

        // Test que la vérification échoue avec un hash incorrect
        let result = verify_pow(nonce, data, timestamp, wrong_hash);
        assert!(result.is_err(), "La vérification aurait dû échouer avec un mauvais hash.");
    }
}
