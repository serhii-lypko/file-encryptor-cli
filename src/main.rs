use std::io::{Error as IOError, Read};
use std::{fs::File, io::Write};

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Error as AesError, Key, Nonce as AesNonce,
};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

use serde::{Deserialize, Serialize};

/// In production, it is crucial to use a unique, securely generated salt for each user
/// or encryption task to enhance security and mitigate the risk of attacks such as
/// rainbow table and brute-force attacks. The current implementation - is a playground.
const SALT: &str = "a9#Bf7@nS2r@1%vH34^sG8&n3k!Xz+L0pQ5!";

const ENCRYPTED_FILE_PATH: &str = "data.aes";

type Nonce = AesNonce<typenum::U12>;

#[derive(Serialize, Deserialize)]
struct EncryptionMetadata {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl EncryptionMetadata {
    pub fn new(nonce: Nonce, ciphertext: Vec<u8>) -> Self {
        let nonce = nonce.to_vec();
        EncryptionMetadata { nonce, ciphertext }
    }

    pub fn write_to_file(&self, file_path: &str) -> Result<(), IOError> {
        let metadata_bytes = match bincode::serialize(&self) {
            Ok(data) => data,
            Err(e) => return Err(IOError::new(std::io::ErrorKind::Other, e)),
        };

        let mut file = File::create(file_path)?;
        file.write_all(&metadata_bytes)?;

        Ok(())
    }

    pub fn read_from_file(file_path: &str) -> Result<Self, IOError> {
        let metadata_bytes = read_file(file_path)?;

        let encryption_metadata = match bincode::deserialize(&metadata_bytes) {
            Ok(metadata) => metadata,
            Err(e) => return Err(IOError::new(std::io::ErrorKind::Other, e)),
        };

        Ok(encryption_metadata)
    }
}

fn derive_key_from_password(password: String) -> Key<Aes256Gcm> {
    let iterations_num = 100_000;

    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        SALT.as_bytes(),
        iterations_num,
        &mut key,
    );
    let key = Key::<Aes256Gcm>::from_slice(&key);

    *key
}

fn read_file(file_path: &str) -> Result<Vec<u8>, IOError> {
    let mut file = File::open(file_path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    Ok(contents)
}

fn encrypt_file(
    plaintext_file_path: &str,
    encrypted_file_path: &str,
    password: String,
) -> Result<(), AesError> {
    let key = derive_key_from_password(password);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let cipher = Aes256Gcm::new(&key);

    let plaintext = read_file(plaintext_file_path).expect("Can't read file data");
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_slice())?;

    let encryption_metadata = EncryptionMetadata::new(nonce, ciphertext);

    // TODO: use logger
    match encryption_metadata.write_to_file(encrypted_file_path) {
        Ok(_) => println!("Successfully encrypted"),
        Err(_) => println!("Error while doing encryption"),
    }

    Ok(())
}

fn decrypt_file(encrypted_file_path: &str, password: String) -> Result<(), AesError> {
    let key = derive_key_from_password(password);

    let encryption_metadata =
        EncryptionMetadata::read_from_file(encrypted_file_path).expect("Can't read encrypted file");

    let nonce: Nonce = AesNonce::clone_from_slice(&encryption_metadata.nonce);

    let cipher = Aes256Gcm::new(&key);
    let plaintext = cipher.decrypt(&nonce, encryption_metadata.ciphertext.as_ref())?;

    dbg!(String::from_utf8(plaintext).unwrap());

    Ok(())
}

fn main() -> Result<(), AesError> {
    // TODO: need to pass encryption file path
    encrypt_file("text.txt", ENCRYPTED_FILE_PATH, String::from("password"))?;
    // decrypt_file("data.aes", String::from("password"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_and_read_encryption_metadata() {
        let file_path = "test_data.aes";

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = vec![1, 2, 3, 4, 5];
        let metadata = EncryptionMetadata::new(nonce, ciphertext);

        metadata.write_to_file(file_path).unwrap();
        let read_metadata = EncryptionMetadata::read_from_file(file_path).unwrap();

        assert_eq!(read_metadata.ciphertext, vec![1, 2, 3, 4, 5]);

        // Delete the file after the test is completed
        std::fs::remove_file(file_path).unwrap();
    }
}
