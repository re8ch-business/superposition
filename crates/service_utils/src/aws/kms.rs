use crate::helpers::get_from_env_unsafe;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use aws_sdk_kms::{Client, primitives::Blob};
use base64::{Engine, engine::general_purpose};
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

const LOCAL_KEY_FILE_ENV: &str = "LOCAL_KMS_KEY_FILE";
const LOCAL_CIPHERTEXT_PREFIX: &str = "local:v1:";

pub fn local_key_configured() -> bool {
    std::env::var_os(LOCAL_KEY_FILE_ENV).is_some()
}

fn decrypt_local(key_name: &str, ciphertext: &str) -> String {
    let path = std::env::var(LOCAL_KEY_FILE_ENV)
        .expect("LOCAL_KMS_KEY_FILE must be set for local decryption");
    decrypt_local_with_file(Path::new(&path), key_name, ciphertext)
}

fn decrypt_local_with_file(path: &Path, key_name: &str, ciphertext: &str) -> String {
    assert!(path.is_absolute(), "LOCAL_KMS_KEY_FILE must be absolute");
    let metadata = fs::symlink_metadata(path).expect("Cannot stat local KMS key file");
    assert!(
        metadata.file_type().is_file(),
        "Local KMS key must be a regular file"
    );
    assert_eq!(
        metadata.permissions().mode() & 0o077,
        0,
        "Local KMS key permissions are too broad"
    );
    assert_eq!(
        metadata.permissions().mode() & 0o222,
        0,
        "Local KMS key must be read-only"
    );
    let key = fs::read(path).expect("Cannot read local KMS key file");
    assert_eq!(key.len(), 32, "Local KMS key must be exactly 32 bytes");
    let payload = ciphertext
        .strip_prefix(LOCAL_CIPHERTEXT_PREFIX)
        .expect("Secret is not in local:v1 format");
    let bytes = general_purpose::STANDARD
        .decode(payload)
        .expect("Invalid local KMS ciphertext encoding");
    assert!(bytes.len() >= 28, "Local KMS ciphertext is too short");
    let cipher = Aes256Gcm::new_from_slice(&key).expect("Invalid local KMS key");
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&bytes[..12]),
            Payload {
                msg: &bytes[12..],
                aad: key_name.as_bytes(),
            },
        )
        .expect("Local KMS decryption failed");
    String::from_utf8(plaintext).expect("Local KMS plaintext is not UTF-8")
}

#[cfg(test)]
mod local_tests {
    use super::*;
    use aes_gcm::aead::Aead;
    use std::{io::Write, os::unix::fs::OpenOptionsExt};

    #[test]
    fn local_ciphertext_is_bound_to_secret_name() {
        let path = std::env::temp_dir()
            .join(format!("superposition-test-key-{}", std::process::id()));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(&path)
            .expect("create test key");
        let key = [7u8; 32];
        file.write_all(&key).expect("write test key");
        drop(file);
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce = [3u8; 12];
        let encrypted = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: b"example-secret",
                    aad: b"DB_PASSWORD",
                },
            )
            .unwrap();
        let encoded = format!(
            "{LOCAL_CIPHERTEXT_PREFIX}{}",
            general_purpose::STANDARD
                .encode([nonce.as_slice(), encrypted.as_slice()].concat())
        );
        assert_eq!(
            decrypt_local_with_file(&path, "DB_PASSWORD", &encoded),
            "example-secret"
        );
        assert!(
            std::panic::catch_unwind(|| decrypt_local_with_file(
                &path,
                "SUPERPOSITION_TOKEN",
                &encoded
            ))
            .is_err()
        );
        fs::remove_file(path).expect("remove test key");
    }
}

async fn decrypt_helper(aws_kms_cli: Client, key: &str, key_value_env: String) -> String {
    let key_value_enc = general_purpose::STANDARD
        .decode(key_value_env)
        .expect("Input string does not contain valid base 64 characters.");

    let key_value_bytes_result = aws_kms_cli
        .decrypt()
        .ciphertext_blob(Blob::new(key_value_enc))
        .send()
        .await;
    let key_value: String = String::from_utf8(
        key_value_bytes_result
            .unwrap_or_else(|_| panic!("Failed to decrypt {key}"))
            .plaintext()
            .unwrap_or_else(|| panic!("Failed to get plaintext value for {key}"))
            .as_ref()
            .to_vec(),
    )
    .expect("Could not convert to UTF-8");
    key_value
}

pub async fn decrypt(aws_kms_cli: Option<Client>, key: &str) -> String {
    let key_value_env: String =
        get_from_env_unsafe(key).unwrap_or_else(|_| panic!("{key} not present in env"));
    if local_key_configured() {
        decrypt_local(key, &key_value_env)
    } else {
        decrypt_helper(
            aws_kms_cli.expect("AWS KMS client is missing"),
            key,
            key_value_env,
        )
        .await
    }
}

pub async fn decrypt_opt(aws_kms_cli: Option<Client>, key: &str) -> Option<String> {
    let key_value_env: String = get_from_env_unsafe(key).ok()?;
    if local_key_configured() {
        Some(decrypt_local(key, &key_value_env))
    } else {
        Some(
            decrypt_helper(
                aws_kms_cli.expect("AWS KMS client is missing"),
                key,
                key_value_env,
            )
            .await,
        )
    }
}

pub async fn new_client() -> Client {
    let config = aws_config::load_from_env().await;

    aws_sdk_kms::Client::new(&config)
}
