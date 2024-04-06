

#[cfg(test)]
use handlebars::Handlebars;
#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
 
#[test]
fn test_email() {
    use crate::{email::SMTPEmailer, otp};

    sys::env::load();

    sys::env::ls();

    let mut handlebars = Handlebars::new();

    handlebars
        .register_template_file("email", "templates/email.html")
        .unwrap();

    let code = otp();

    let mut data = HashMap::new();
    data.insert("name", "Antony" );
    data.insert("test",&code);

    let body = handlebars.render("email", &data).unwrap();

    println!("{}", body);

    let emailer = SMTPEmailer::new();

    emailer.send_email("antony@antonyholmes.dev", "Yet Another test", &body);


}
