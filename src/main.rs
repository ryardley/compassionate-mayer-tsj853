// use std::{
//     ops::{Add, Mul},
//     sync::Arc,
// };

use std::{
    ops::{Add, Mul},
    sync::Arc,
};

use anyhow::*;
use fhe::bfv::{self, BfvParameters, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
use rand::thread_rng;

// Define a kind of trait for a keypair that encrypts to Ct
trait Keypair {
    fn encrypt(&self, value: u64) -> Result<Ciphertext>;
    fn decrypt(&self, ciphertext: &Ciphertext) -> Result<u64>;
}

struct FheKeypair {
    sk: SecretKey,
    pub pk: PublicKey,
    pub params: Arc<BfvParameters>,
}

impl FheKeypair {
    // might want to pass in rng...
    pub fn generate(params: Arc<BfvParameters>) -> FheKeypair {
        let mut rng = thread_rng();

        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);

        FheKeypair { sk, pk, params }
    }
}

impl Keypair for FheKeypair {
    fn encrypt(&self, value: u64) -> Result<Ciphertext> {
        let mut rng = thread_rng();
        let input1: Vec<u64> = vec![value];
        let pt1 = Plaintext::try_encode(&input1, Encoding::poly(), &self.params)?;
        Ok(self.pk.try_encrypt(&pt1, &mut rng)?)
    }

    fn decrypt(&self, ciphertext: &Ciphertext) -> Result<u64> {
        let decrypted = self.sk.try_decrypt(ciphertext)?;
        let decrypted_vec = Vec::<u64>::try_decode(&decrypted, Encoding::poly())?;
        Ok(decrypted_vec[0])
    }
}

// 1. Also need an algorhythm on the server that takes various ciphertexts as input and operates on
//    them
// 2.

fn triple_product(a: &Ciphertext, b: &Ciphertext, c: &Ciphertext) -> Ciphertext {
    let mut prod = a * b;
    prod = &prod * c;
    prod
}

fn main() -> Result<()> {
    let params = bfv::BfvParametersBuilder::new()
        .set_degree(2048)
        .set_moduli(&[0xffffffffffc0001])
        .set_plaintext_modulus(1 << 8)
        .build_arc()?;

    let keypair = FheKeypair::generate(params);

    let inputs = [2, 4, 10];

    let a = keypair.encrypt(inputs[0])?;
    let b = keypair.encrypt(inputs[1])?;
    let c = keypair.encrypt(inputs[2])?;

    let prod = triple_product(&a,&b,&c);
    
    let tally_result = keypair.decrypt(&prod)?;

    let expected_result: u64 = inputs[0] * inputs[1] * inputs[2];

    println!("\nExpected Result: {:?}", expected_result);
    println!("Decrypted Result: {:?}\n", tally_result);

    if expected_result == tally_result {
        println!("🎉  Successful computation\n");
    } else {
        println!("🙁  Results don't match\n");
    }

    Ok(())
}
