#[cfg(test)]
use crate::email::SMTPEmailer;

#[cfg(test)]
use handlebars::Handlebars;
#[cfg(test)]
use std::collections::HashMap;
#[cfg(test)]
 
#[test]
fn test_email() {
    sys::env::load();

    sys::env::ls();

    let mut handlebars = Handlebars::new();

    handlebars
        .register_template_file("email", "templates/email.html")
        .unwrap();

    let mut data = HashMap::new();
    data.insert("name", "Antony");

    let body = handlebars.render("email", &data).unwrap();

    println!("{}", body);

    let emailer = SMTPEmailer::new();

    emailer.send_email("antony@antonyholmes.dev", "Yet Another test", &body);
}
