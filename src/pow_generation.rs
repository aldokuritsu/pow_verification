use sha2::{Sha256, Digest};
use std::fmt::Write;
use std::time::{SystemTime, Duration, UNIX_EPOCH};

// Durée d'expiration pour un hash valide (en secondes)
// const HASH_EXPIRATION: Duration = Duration::new(10, 0); // 10 secondes

// Fonction pour générer la preuve de travail (PoW)
pub fn mine_block(data: &str, pattern: &str, difficulty: usize) -> Result<(), String> {
    let difficulty_prefix = pattern.repeat(difficulty);
    let mut nonce = 0;
    let mining_start_time = SystemTime::now();

    loop {
        let timestamp = get_current_timestamp()?;
        let input = format!("{}{}{}", data, timestamp, nonce);

        let hash_hex = compute_sha256_hash(&input);

        if hash_hex.starts_with(&difficulty_prefix) {
            let elapsed_time = mining_start_time
                .elapsed()
                .map_err(|_| "Erreur lors du calcul du temps écoulé".to_string())?;

            // if elapsed_time > HASH_EXPIRATION {
            //     return Err("Le hash a expiré ! Nonce invalide.".to_string());
            // }

            // Affichage des informations de succès
            display_success_info(pattern, difficulty, timestamp, nonce, &hash_hex, elapsed_time);
            break;
        }

        nonce += 1;
    }

    Ok(())
}

// Fonction pour obtenir le timestamp actuel en secondes
fn get_current_timestamp() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| "Erreur lors de la récupération du timestamp".to_string())
}

// Fonction pour calculer le hash SHA-256 et le formater en hexadécimal
fn compute_sha256_hash(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let hash_result = hasher.finalize();

    let mut hash_hex = String::new();
    for byte in hash_result.iter() {
        write!(&mut hash_hex, "{:02x}", byte).unwrap();
    }

    hash_hex
}

// Fonction pour afficher les informations après un minage réussi
fn display_success_info(
    pattern: &str,
    difficulty: usize,
    timestamp: u64,
    nonce: u64,
    hash_hex: &str,
    elapsed_time: Duration,
) {
    println!("Bloc miné !");
    println!("Pattern attendu : {}", pattern);
    println!("Difficulté: {}", difficulty);
    println!("Timestamp: {}", timestamp);
    println!("Nonce trouvé: {}", nonce);
    println!("Hash correspondant: {}", hash_hex);
    println!("Temps de minage : {} ms", elapsed_time.as_millis());
}
