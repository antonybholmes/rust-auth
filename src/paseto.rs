 
use rusty_paseto::{
    core::{PasetoAsymmetricPrivateKey, Public, V4},
    generic::{CustomClaim, ExpirationClaim, TokenIdentifierClaim},
    prelude::PasetoBuilder,
};

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::{jwt::TokenType, AuthError, AuthResult};

//PASETO: Platform-Agnostic Security Tokens

pub fn base_pasesto(uuid: &str,
    token_type: &TokenType,
    otp: &str,
    expires: &OffsetDateTime, key: &PasetoAsymmetricPrivateKey::<V4, Public>) -> AuthResult<String> {
    //let in_2_minutes = ( OffsetDateTime::now_utc() +  Duration::minutes(2)); //.format(&Rfc3339)?;

    match PasetoBuilder::<V4, Public>::default()
        .set_claim(ExpirationClaim::try_from(expires.format(&Rfc3339)?)?)
        .set_claim(TokenIdentifierClaim::from(uuid))
        .set_claim(CustomClaim::try_from(("type", token_type.to_string()))?)
        .set_claim(CustomClaim::try_from(("otp", otp))?)
        .build(key) {
            Ok(paseto) => Ok(paseto),
            Err(err) => Err(AuthError::JWTError(err.to_string())),
        }
}

// pub fn create_paseto_key() {
//     println!("j f");

//     //let private_key = Key::<64>::try_from("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")?;
//     let k = Key::<64>::try_from("93b2e7e6fdea36ddf2191bf6b515d1aab4c4e601ddefbd6fac817de8b7fac9c39e32f773788c46d28a03a3a86c5db17a7e1f99adb7ff1ce2099e93cf2ec89d84").unwrap();
//     let private_key = PasetoAsymmetricPrivateKey::<V4, Public>::try_from(k.as_slice()).unwrap();
//     let public_key =
//         Key::<32>::try_from("9e32f773788c46d28a03a3a86c5db17a7e1f99adb7ff1ce2099e93cf2ec89d84")
//             .unwrap();
//     let public_key = PasetoAsymmetricPublicKey::<V4, Public>::from(&public_key);

//     let token = PasetoBuilder::<V4, Public>::default()
//         .set_claim(AudienceClaim::from("customers"))
//         .build(&private_key)
//         .unwrap();

//     println!("{}", token);

//     let json = PasetoParser::<V4, Public>::default()
//         .parse(&token, &public_key)
//         .unwrap();

//     println!("j {}", json["aud"]);
// }

/**
 * Although poorly, documented, paseto uses concatenation of the private and public keys
 * as hex, so we can use the ed25519-dalek lib to create this for us.
 */
pub fn generate_key() {
    let mut csprng = OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);

    let verifying_key: VerifyingKey = signing_key.verifying_key();

    println!("private {}", hex::encode(signing_key.to_bytes()));
    println!("public {}", hex::encode(verifying_key.to_bytes()));

    println!(
        "sign {}{}",
        hex::encode(signing_key.to_bytes()),
        hex::encode(verifying_key.to_bytes())
    );
}
