use lettre::{
    message::header::ContentType, transport::smtp::authentication::Credentials, Message,
    SmtpTransport, Transport,
};
use once_cell::sync::Lazy;

#[derive(Debug, Clone)]
pub struct SMTPEmailer {
    //name: String,
    user: String,
    password: String,

    //host: String,
    //port: u32,
    //addr: String,
    reply_to: String,
    mailer: SmtpTransport,
}

impl SMTPEmailer {
    pub fn new() -> SMTPEmailer {
        let name = sys::env::str("SMTP_NAME");
        let from = sys::env::str("SMTP_FROM");
        let user = sys::env::str("SMTP_USER");
        let password = sys::env::str("SMTP_PASSWORD");
        let host = sys::env::str("SMTP_HOST");
        //let port = env::u32("SMTP_PORT");
        //let addr = format!("{}:{}", host, port);

        let reply_to = format!("{} <{}>", name, from);

        println!("aha {}", reply_to);

        let creds = Credentials::new(user.clone(), password.clone());

        // Open a remote connection to gmail
        let mailer = SmtpTransport::relay(&host)
            .unwrap()
            .credentials(creds)
            .build();

        SMTPEmailer {
            //name,
            user,
            password,
            //host,
            //port,
            reply_to,

            mailer,
        }
    }

    pub fn set_host(&mut self, host: &str) -> &mut Self {
        let mailer = SmtpTransport::relay(&host)
            .unwrap()
            .credentials(Credentials::new(self.user.clone(), self.password.clone()))
            .build();

        self.mailer = mailer;

        self
    }

    pub fn send_email(&self, to: &str, subject: &str, body: &str) {
        let email = Message::builder()
            .from(self.reply_to.parse().unwrap())
            .reply_to(self.reply_to.parse().unwrap())
            .to(to.parse().unwrap())
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(body.to_string())
            .unwrap();

        match self.mailer.send(&email) {
            Ok(_) => println!("Email sent successfully!"),
            Err(e) => println!("Could not send email: {e:?}"),
        }
    }
}

pub static EMAILER: Lazy<SMTPEmailer> = Lazy::new(|| SMTPEmailer::new());
