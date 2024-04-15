use std::fmt::Display;

use askama::Template;
use lettre::{
    message::header::ContentType, transport::smtp::authentication::Credentials, Message,
    SmtpTransport, Transport,
};

pub const VALID_TEN_MINS: &str = "10 minutes";
pub const DO_NOT_REPLY: &str = "Please do not reply to this message. It was sent from a notification-only email address that we don't monitor.";
pub const TOKEN_PARAM: &str = "token";
pub const URL_PARAM: &str = "url";

#[derive(Template)]
#[template(path = "email/passwordless/api.html")]
pub struct PasswordlessEmailTemplate {
    pub name: String,
    pub link: String,
    pub time: String,
    pub do_not_reply: String,
}

#[derive(Template)]
#[template(path = "email/passwordless/web.html")]
pub struct PasswordlessEmailWebTemplate {
    pub name: String,
    pub link: String,
    pub time: String,
    pub do_not_reply: String,
}

#[derive(Template)]
#[template(path = "email/verify/api.html")]
pub struct EmailVerificationTemplate {
    pub name: String,
    pub link: String,
    pub time: String,
    pub do_not_reply: String,
}

#[derive(Template)]
#[template(path = "email/verify/web.html")]
pub struct EmailVerificationWebTemplate {
    pub name: String,
    pub link: String,
    pub time: String,
    pub do_not_reply: String,
}

#[derive(Template)]
#[template(path = "email/verified.html")]
pub struct EmailVerifiedTemplate {
    pub name: String,
    pub do_not_reply: String,
}

#[derive(Debug, Clone)]
pub enum MailerError {
    SendError(String),
    HtmlEmailError(String),
}

//impl std::error::Error for MailerError {}

//impl std::error::Error for AuthError {}

impl Display for MailerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SendError(message) => {
                write!(f, "could not send email: {}", message)
            }
            Self::HtmlEmailError(message) => {
                write!(f, "could not send HTML email: {}", message)
            }
        }
    }
}

// impl IntoResponse for MailerError {
//     fn into_response(self) -> Response {
//         (StatusCode::BAD_REQUEST, self.to_string()).into_response()
//     }
// }

impl From<lettre::error::Error> for MailerError {
    fn from(error: lettre::error::Error) -> Self {
        MailerError::SendError(error.to_string())
    }
}

impl From<askama::Error> for MailerError {
    fn from(error: askama::Error) -> Self {
        MailerError::SendError(error.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct Mailer {
    //name: String,
    //user: String,
    //password: String,

    //host: String,
    //port: u32,
    //addr: String,
    reply_to: String,
    mailer: SmtpTransport,
}

impl Mailer {
    pub fn new() -> Self {
        let name = sys::env::str("SMTP_NAME");
        let from = sys::env::str("SMTP_FROM");
        let user = sys::env::str("SMTP_USER");
        let password = sys::env::str("SMTP_PASSWORD");
        let host = sys::env::str("SMTP_HOST");
        //let port = env::u32("SMTP_PORT");
        //let addr = format!("{}:{}", host, port);

        let reply_to = format!("{} <{}>", name, from);

        let creds = Credentials::new(user, password);

        // Open a remote connection to gmail
        let mailer = SmtpTransport::relay(&host)
            .unwrap()
            .credentials(creds)
            .build();

        Mailer { reply_to, mailer }
    }

    // pub fn set_host(&mut self, host: &str) -> &mut Self {
    //     let mailer = SmtpTransport::relay(&host)
    //         .unwrap()
    //         .credentials(Credentials::new(self.user.clone(), self.password.clone()))
    //         .build();

    //     self.mailer = mailer;

    //     self
    // }

    pub fn send_html_email<T: Template>(
        &self,
        to: &str,
        subject: &str,
        body: &T,
    ) -> Result<(), MailerError> {
        let html = body.render()?;

        let email = Message::builder()
            .from(self.reply_to.parse().unwrap())
            .reply_to(self.reply_to.parse().unwrap())
            .to(to.parse().unwrap())
            .subject(subject)
            .header(ContentType::TEXT_HTML)
            .body(html)?;

        match self.mailer.send(&email) {
            Ok(_) => eprintln!("HTML email sent successfully!"),
            Err(e) => return Err(MailerError::SendError(e.to_string())),
        }

        Ok(())
    }

    pub fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<(), MailerError> {
        return self.send_base_email(to, subject, body, ContentType::TEXT_PLAIN);
    }

    pub fn send_base_email(
        &self,
        to: &str,
        subject: &str,
        body: &str,
        content_type: ContentType,
    ) -> Result<(), MailerError> {
        let email = Message::builder()
            .from(self.reply_to.parse().unwrap())
            .reply_to(self.reply_to.parse().unwrap())
            .to(to.parse().unwrap())
            .subject(subject)
            .header(content_type)
            .body(body.to_string())?;

        match self.mailer.send(&email) {
            Ok(_) => eprintln!("Email sent successfully!"),
            Err(e) => return Err(MailerError::SendError(e.to_string())),
        }

        Ok(())
    }
}

//pub static EMAILER: Lazy<SMTPEmailer> = Lazy::new(|| SMTPEmailer::new());
