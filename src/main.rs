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

#[derive(Serialize, Deserialize)]
struct EncryptedFileData {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl EncryptedFileData {
    pub fn new(nonce: Nonce, ciphertext: Vec<u8>) -> Self {
        let nonce_vec = nonce.to_vec();

        EncryptedFileData {
            nonce: nonce_vec,
            ciphertext,
        }
    }

    // TODO: error handling
    pub fn write_to_file(&self) {
        let serialized_data = bincode::serialize(&self).unwrap();

        let mut file = File::create("data.aes").unwrap();
        file.write_all(&serialized_data).unwrap();
    }

    // TODO: error handling
    pub fn read_from_file() -> Self {
        let file_data = read_file_data("data.aes").unwrap();
        bincode::deserialize(&file_data).unwrap()
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

fn encrypt_plaintext(
    plaintext: &[u8],
    key: Key<Aes256Gcm>,
    nonce: Nonce,
) -> Result<Vec<u8>, AesError> {
    let cipher = Aes256Gcm::new(&key);
    let ciphertext = cipher.encrypt(&nonce, plaintext)?;

    Ok(ciphertext)
}

fn decrypt_ciphertext(
    ciphertext: Vec<u8>,
    key: Key<Aes256Gcm>,
    nonce: Nonce,
) -> Result<Vec<u8>, AesError> {
    let cipher = Aes256Gcm::new(&key);
    let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref())?;

    Ok(plaintext)
}

fn read_file_data(file_path: &str) -> Result<Vec<u8>, std::io::Error> {
    let mut file = File::open(file_path).unwrap();
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;

    Ok(contents)
}

fn main() -> Result<(), AesError> {
    let key = derive_key_from_password(String::from("password"));
    // let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // let plaintext = read_file_data("text.txt").unwrap();
    // let ciphertext = encrypt_plaintext(plaintext.as_slice(), key, nonce).unwrap();

    // let encrypted_file_data = EncryptedFileData::new(nonce, ciphertext);
    // encrypted_file_data.write_to_file();

    let encrypted_file_data = EncryptedFileData::read_from_file();

    let nonce: Nonce = AesNonce::clone_from_slice(&encrypted_file_data.nonce);

    let plaintext = decrypt_ciphertext(encrypted_file_data.ciphertext, key, nonce).unwrap();

    dbg!(String::from_utf8(plaintext).unwrap());

    Ok(())
}

// NOTE: don't delete
// let nonce_vec = nonce.to_vec();
// let nonce: Nonce = AesNonce::clone_from_slice(&nonce_vec);
