use std::io::Read;
use std::{fs::File, io::Write};

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Error as AesError, Key, Nonce as AesNonce,
};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

use serde::{Deserialize, Serialize};

type Nonce = AesNonce<typenum::U12>;

// TODO: tests
// TODO: logging

#[derive(Serialize, Deserialize)]
struct EncryptionMetadata {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl EncryptionMetadata {
    pub fn new(nonce: Nonce, ciphertext: Vec<u8>) -> Self {
        let nonce_vec = nonce.to_vec();

        EncryptionMetadata {
            nonce: nonce_vec,
            ciphertext,
        }
    }

    pub fn write_to_file(&self) -> Result<(), std::io::Error> {
        // FIXME: unwrap
        let serialized_data = bincode::serialize(&self).unwrap();

        let mut file = File::create("data.aes")?;
        file.write_all(&serialized_data)?;

        Ok(())
    }

    pub fn read_from_file(file_path: &str) -> Result<Self, std::io::Error> {
        let plaintext = read_file_plaintext(file_path)?;

        // FIXME: unwrap
        let encryption_metadata = bincode::deserialize(&plaintext).unwrap();

        Ok(encryption_metadata)
    }
}

fn derive_key_from_password(password: String) -> Key<Aes256Gcm> {
    let salt = b"salt";

    // TODO: increase for real usage
    let iterations_num = 1000;

    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations_num, &mut key);
    let key = Key::<Aes256Gcm>::from_slice(&key);

    *key
}

fn read_file_plaintext(file_path: &str) -> Result<Vec<u8>, std::io::Error> {
    let mut file = File::open(file_path)?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    Ok(contents)
}

fn encrypt_file(file_path: &str, password: String) -> Result<(), AesError> {
    let key = derive_key_from_password(password);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let cipher = Aes256Gcm::new(&key);

    let plaintext = read_file_plaintext(file_path).expect("Can't read file data");
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_slice())?;

    let encryption_metadata = EncryptionMetadata::new(nonce, ciphertext);

    // TODO: use logger
    match encryption_metadata.write_to_file() {
        Ok(_) => println!("Successfully encrypted"),
        Err(_) => println!("Error while doing encryption"),
    }

    Ok(())
}

fn decrypt_file(file_path: &str, password: String) -> Result<(), AesError> {
    let key = derive_key_from_password(password);

    let encryption_metadata =
        EncryptionMetadata::read_from_file(file_path).expect("Can't read encrypted file");

    let nonce: Nonce = AesNonce::clone_from_slice(&encryption_metadata.nonce);

    let cipher = Aes256Gcm::new(&key);
    let plaintext = cipher.decrypt(&nonce, encryption_metadata.ciphertext.as_ref())?;

    dbg!(String::from_utf8(plaintext).unwrap());

    Ok(())
}

fn main() -> Result<(), AesError> {
    // encrypt_file("text.txt", String::from("password"))?;
    decrypt_file("data.aes", String::from("password"))?;

    Ok(())
}
