use std::fs::File;
use std::io::Read;

use jwt_simple::prelude::*;
use base64::prelude::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Read the public key file
    let mut file = File::open("./hack/auth/public_key.pem")?;
    let mut public_key_pem = String::new();
    file.read_to_string(&mut public_key_pem)?;

    // Create an RSA 256 key
    let public_key = RS256PublicKey::from_pem(&public_key_pem)?;
    let comps = public_key.to_components();

    println!("e: {}", BASE64_URL_SAFE_NO_PAD.encode(&comps.e));
    println!("n: {}", BASE64_URL_SAFE_NO_PAD.encode(&comps.n));

    println!("e: {:?}", &comps.e);
    println!("n: {:?}", &comps.n);
    println!("Successfully created RSA 256 key");
    Ok(())
}