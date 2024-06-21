use fhe::bfv::{self, Encoding, Plaintext, PublicKey, SecretKey};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
use rand::thread_rng;
use std::error::Error;

// refactor: keypair trait
//

fn main() -> Result<(), Box<dyn Error>> {
    //    let degree = 2048;
    //   let plaintext_modulus: u64 = 4096;
    // let moduli = vec![0xffffee001];

    let params = bfv::BfvParametersBuilder::new()
        .set_degree(2048)
        .set_moduli(&[0xffffffffffc0001])
        .set_plaintext_modulus(1 << 9)
        .build_arc()?;

    let mut rng = thread_rng();
    let sk = SecretKey::random(&params, &mut rng);
    let pk = PublicKey::new(&sk, &mut rng);

    let input1: Vec<u64> = vec![2];
    let input2: Vec<u64> = vec![4];
    let input3: Vec<u64> = vec![10];

    let pt1 = Plaintext::try_encode(&input1, Encoding::poly(), &params)?;
    let pt2 = Plaintext::try_encode(&input2, Encoding::poly(), &params)?;
    let pt3 = Plaintext::try_encode(&input3, Encoding::poly(), &params)?;

    let ct1 = pk.try_encrypt(&pt1, &mut rng)?;
    let ct2 = pk.try_encrypt(&pt2, &mut rng)?;
    let ct3 = pk.try_encrypt(&pt3, &mut rng)?;

    let mut prod = &ct1 * &ct2;
    prod = &prod * &ct3;

    let decrypted = sk.try_decrypt(&prod)?;
    let tally_vec = Vec::<u64>::try_decode(&decrypted, Encoding::poly())?;
    let tally_result = tally_vec[0];

    let expected_result: u64 = input1[0] * input2[0] * input3[0];

    println!("\nExpected Result: {:?}", expected_result);
    println!("Decrypted Result: {:?}\n", tally_result);

    if expected_result == tally_result {
        println!("🎉  Successful computation\n");
    } else {
        println!("🙁  Results don't match\n");
    }

    Ok(())
}
