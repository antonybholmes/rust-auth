

#[cfg(test)]
use askama::Template;
 
#[cfg(test)]
use crate::paseto::generate_key;
 
#[cfg(test)]
#[derive(Template)]
#[template(path = "email/verify/api.html")]
struct EmailTemplate {
    name: String,
    link: String,
    time: String,
    do_not_reply: String,
}

 
// fn test_email() {
//     use crate::{email::Mailer, otp};

//     sys::env::load();

//     sys::env::ls();

//     let mut handlebars = Handlebars::new();

//     handlebars
//         .register_template_file("email", "templates/email.html")
//         .unwrap();

//     let code = otp();

//     let mut data = HashMap::new();
//     data.insert("name", "Antony" );
//     data.insert("test",&code);

//     let body = handlebars.render("email", &data).unwrap();

//     println!("{}", body);

//     let emailer = Mailer::new();

//     emailer.send_email("antony@antonyholmes.dev", "Yet Another test", &body);


// }

// #[test]
// fn test_paseto() {
//     eprintln!("sdfsdf");
//     create_paseto();
// }

#[test]
fn test_generate_key() {
 
    generate_key();
}