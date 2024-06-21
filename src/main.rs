use anyhow::*;
use fhe::bfv::{self, BfvParameters, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
use rand::thread_rng;
use std::collections::VecDeque;
use std::ops::Add;
use std::ops::Mul;
use std::sync::Arc;

trait Encryptor<U, T> {
    fn encrypt(&self, value: U) -> Result<T>;
}

trait Decryptor<U, T>
where
    for<'a> &'a T: Mul<&'a T, Output = T>,
{
    fn decrypt(&self, ciphertext: &T) -> Result<U>;
}

struct FheKeypair {
    sk: SecretKey,
    pub pk: PublicKey,
    pub params: Arc<BfvParameters>,
}

impl FheKeypair {
    pub fn generate(params: Arc<BfvParameters>) -> FheKeypair {
        let mut rng = thread_rng();

        let sk = SecretKey::random(&params, &mut rng);
        let pk = PublicKey::new(&sk, &mut rng);

        FheKeypair { sk, pk, params }
    }
}

fn encrypt_u64_ciphertext(
    params: &Arc<BfvParameters>,
    pk: &PublicKey,
    value: u64,
) -> Result<Ciphertext> {
    let mut rng = thread_rng();
    let input1: Vec<u64> = vec![value];
    let pt1 = Plaintext::try_encode(&input1, Encoding::poly(), &params)?;
    Ok(pk.try_encrypt(&pt1, &mut rng)?)
}

impl Encryptor<u64, Ciphertext> for FheKeypair {
    fn encrypt(&self, value: u64) -> Result<Ciphertext> {
        encrypt_u64_ciphertext(&self.params, &self.pk, value)
    }
}

impl Encryptor<Vec<u64>, Vec<Ciphertext>> for FheKeypair {
    fn encrypt(&self, value: Vec<u64>) -> Result<Vec<Ciphertext>> {
        let mut output = vec![];
        for input in value {
            output.push(encrypt_u64_ciphertext(&self.params, &self.pk, input)?);
        }
        Ok(output)
    }
}

impl Decryptor<u64, Ciphertext> for FheKeypair {
    fn decrypt(&self, ciphertext: &Ciphertext) -> Result<u64> {
        let decrypted = self.sk.try_decrypt(ciphertext)?;
        let decrypted_vec = Vec::<u64>::try_decode(&decrypted, Encoding::poly())?;
        Ok(decrypted_vec[0])
    }
}

// This is a severside algorythm it would need to be defined by some kind of serializable DSL that
// defines the scope of each operation.
// this means you would want to break this down into a DSL to create circuits.
// ie. DSL -> server alongside inputs.
// tokenization -> lex -> parse -> functions -> process inputs
// (mul (mul a b) c)
// you can do this by using a for loop and a stack
// iterate over the lisp
// first thing is a varadic function or op code
// depending on the function type you know what its arity is
// eg mul has two inputs

enum Instruction {
    Arg(u64),
    Mul, // Add
}

type OperationFn<T> = Box<dyn Fn(T, T) -> T>;

fn parse<T>(program: Vec<Instruction>, mul: OperationFn<T>) -> impl Fn(Vec<T>) -> T {
    move |args: Vec<T>| {
        let mut args = VecDeque::from(args);
        let mut stack = Vec::new();

        for instruction in program.iter() {
            match instruction {
                Instruction::Arg(_) => {
                    if let Some(arg) = args.pop_front() {
                        stack.push(arg);
                    } else {
                        panic!("Not enough arguments provided");
                    }
                }
                Instruction::Mul => {
                    let b = stack.pop().expect("Stack underflow");
                    let a = stack.pop().expect("Stack underflow");
                    stack.push(mul(a, b));
                }
            }
        }

        stack.pop().expect("Program did not produce a result")
    }
}

type I = Instruction;
fn main() -> Result<()> {
    let params = bfv::BfvParametersBuilder::new()
        .set_degree(2048)
        .set_moduli(&[0xffffffffffc0001])
        .set_plaintext_modulus(1 << 8)
        .build_arc()?;

    // Clientside
    let keypair = FheKeypair::generate(params);

    let inputs = vec![2u64, 4u64, 10u64];
    let expected_result: u64 = inputs[0] * inputs[1] * inputs[2];
    let encrypted = keypair.encrypt(inputs)?;

    // Serverside
    let program = vec![
        I::Arg(0),
        I::Arg(1),
        I::Mul,
        I::Arg(2),
        I::Mul,
    ];
    
    let mul: OperationFn<Ciphertext> = Box::new(|a, b| &a * &b);

    let execute = parse(program, mul);

    let output = execute(encrypted);
    // Clientside
    let tally_result = keypair.decrypt(&output)?;

    println!("\nExpected Result: {:?}", expected_result);
    println!("Decrypted Result: {:?}\n", tally_result);

    if expected_result == tally_result {
        println!("🎉  Successful computation\n");
    } else {
        println!("🙁  Results don't match\n");
    }

    Ok(())
}
