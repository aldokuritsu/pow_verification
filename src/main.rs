mod pow_generation;
mod pow_verification;
use std::env;

fn main() {
    // Récupérer les arguments de la ligne de commande
    let args: Vec<String> = env::args().collect();

    // Vérification des arguments pour définir si on mine ou vérifie un PoW
    if args.len() < 2 {
        eprintln!("Usage: {} <mine|verify> [arguments...]", args[0]);
        std::process::exit(1);
    }

    let command = &args[1];

    match command.as_str() {
        "mine" => {
            if args.len() < 4 {
                eprintln!("Usage: {} mine <data> <pattern> [difficulty]", args[0]);
                std::process::exit(1);
            }

            let data = &args[2];
            let pattern = &args[3];
            let difficulty: usize = if args.len() > 4 {
                args[4].parse().unwrap_or(1)
            } else {
                1 // Par défaut, une difficulté de 1
            };

            // Générer le bloc (Preuve de Travail)
            if let Err(e) = pow_generation::mine_block(data, pattern, difficulty) {
                eprintln!("{}", e);
            }
        }

        "verify" => {
            if args.len() < 6 {
                eprintln!("Usage: {} verify <nonce> <data> <timestamp> <expected_hash>", args[0]);
                std::process::exit(1);
            }

            let nonce: u64 = args[2].parse().expect("Le nonce doit être un entier");
            let data = &args[3];
            let timestamp: u64 = args[4].parse().expect("Le timestamp doit être un entier");
            let expected_hash = &args[5];

            // Vérifier la preuve de travail
            match pow_verification::verify_pow(nonce, data, timestamp, expected_hash) {
                Ok(_) => println!("PoW valide !"),
                Err(error) => eprintln!("{}", error),
            }
        }

        _ => {
            eprintln!("Commande non reconnue : {}", command);
            eprintln!("Utilisez 'mine' ou 'verify'.");
        }
    }
}
