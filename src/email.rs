use std::fmt::Display;

use askama::Template;
use axum::{http::StatusCode, response::{IntoResponse, Response}};
use lettre::{
    message::header::ContentType, transport::smtp::authentication::Credentials, Message,
    SmtpTransport, Transport,
};

pub const DO_NOT_REPLY: &str = "Please do not reply to this message. It was sent from a notification-only email address that we don't monitor.";
pub const TOKEN_PARAM: &str = "token";
pub const URL_PARAM: &str = "url";

#[derive(Debug, Clone)]
pub enum EmailError {
    SendError(String),
    HtmlEmailError(String)
}

impl std::error::Error for EmailError {}

//impl std::error::Error for AuthError {}

impl Display for EmailError {
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

impl IntoResponse for EmailError {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, self.to_string()).into_response()
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

        let creds = Credentials::new(user.clone(), password.clone());

        // Open a remote connection to gmail
        let mailer = SmtpTransport::relay(&host)
            .unwrap()
            .credentials(creds)
            .build();

        Mailer {
            //user,
            //password,
            reply_to,
            mailer,
        }
    }

    // pub fn set_host(&mut self, host: &str) -> &mut Self {
    //     let mailer = SmtpTransport::relay(&host)
    //         .unwrap()
    //         .credentials(Credentials::new(self.user.clone(), self.password.clone()))
    //         .build();

    //     self.mailer = mailer;

    //     self
    // }

    pub fn send_html_email<T:Template>(&self, to: &str, subject: &str, body: &T) ->Result<(), EmailError> {
        
        let html = match body.render() {
            Ok(v)=>v,
            Err(e) =>return Err(EmailError::HtmlEmailError(e.to_string())),
        };

        return self.send_base_email(to, subject, &html, ContentType::TEXT_HTML);
    }

    pub fn send_email(&self, to: &str, subject: &str, body: &str) ->Result<(), EmailError> {
         

        return self.send_base_email(to, subject, body, ContentType::TEXT_PLAIN)
    }

    pub fn send_base_email(&self, to: &str, subject: &str, body: &str, content_type: ContentType) ->Result<(), EmailError> {
        let email = Message::builder()
            .from(self.reply_to.parse().unwrap())
            .reply_to(self.reply_to.parse().unwrap())
            .to(to.parse().unwrap())
            .subject(subject)
            .header(content_type)
            .body(body.to_string())
            .unwrap();
 
        match self.mailer.send(&email) {
            Ok(_) => println!("Email sent successfully!"),
            Err(e) => return Err(EmailError::SendError(e.to_string())),
        }

        Ok(())
    }
}

//pub static EMAILER: Lazy<SMTPEmailer> = Lazy::new(|| SMTPEmailer::new());
