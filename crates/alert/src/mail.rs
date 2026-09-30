//! Mailversand per SMTP.

use lettre::message::Mailbox;
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use std::time::Duration;

/// Verschlüsselung der SMTP-Verbindung.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Security {
    /// Klartext-Verbindung, danach STARTTLS (Pflicht) – üblich auf Port 587
    StartTls,
    /// TLS ab dem ersten Byte – üblich auf Port 465
    Tls,
    /// Unverschlüsselt – nur für einen Relay im eigenen Netz (Port 25)
    None,
}

impl Security {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "starttls" => Some(Self::StartTls),
            "tls" | "ssl" => Some(Self::Tls),
            "none" | "plain" => Some(Self::None),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MailConfig {
    pub host: String,
    pub port: u16,
    pub security: Security,
    /// Leer = ohne Anmeldung
    pub username: String,
    pub password: String,
    /// Absender, z. B. `Snia-Net-Mon <netmon@example.org>`
    pub from: String,
    /// Empfänger (Admins)
    pub to: Vec<String>,
    pub timeout: Duration,
}

/// Versandbereiter SMTP-Client. Günstig zu klonen.
#[derive(Clone)]
pub struct Mailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
    to: Vec<Mailbox>,
}

impl Mailer {
    /// Konfiguration prüfen (Adressen, Host) – verbindet noch nicht.
    pub fn new(config: &MailConfig) -> Result<Self, String> {
        let from: Mailbox = config.from.trim().parse().map_err(|e| format!("from {:?}: {e}", config.from))?;
        let to = config
            .to
            .iter()
            .filter(|a| !a.trim().is_empty())
            .map(|a| a.trim().parse::<Mailbox>().map_err(|e| format!("Empfänger {a:?}: {e}")))
            .collect::<Result<Vec<_>, _>>()?;
        if to.is_empty() {
            return Err("keine Empfänger (admins) eingetragen".into());
        }
        let host = config.host.trim();
        let builder = match config.security {
            Security::StartTls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host).map_err(|e| format!("smtp_host {host:?}: {e}"))?,
            Security::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(host).map_err(|e| format!("smtp_host {host:?}: {e}"))?,
            Security::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host),
        };
        let mut builder = builder.port(config.port).timeout(Some(config.timeout));
        if !config.username.trim().is_empty() {
            builder = builder.credentials(Credentials::new(config.username.trim().to_string(), config.password.clone()));
        }
        Ok(Self { transport: builder.build(), from, to })
    }

    pub fn recipients(&self) -> String {
        self.to.iter().map(|m| m.email.to_string()).collect::<Vec<_>>().join(", ")
    }

    /// Klartext-Mail an alle Empfänger senden.
    pub async fn send(&self, subject: &str, body: &str) -> Result<(), String> {
        let mut message = Message::builder().from(self.from.clone()).subject(subject).header(ContentType::TEXT_PLAIN);
        for to in &self.to {
            message = message.to(to.clone());
        }
        let message = message.body(body.to_string()).map_err(|e| e.to_string())?;
        self.transport.send(message).await.map(|_| ()).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> MailConfig {
        MailConfig {
            host: "mail.example.org".into(),
            port: 587,
            security: Security::StartTls,
            username: String::new(),
            password: String::new(),
            from: "Snia-Net-Mon <netmon@example.org>".into(),
            to: vec!["admin@example.org".into(), " ".into()],
            timeout: Duration::from_secs(5),
        }
    }

    #[test]
    fn config_is_validated() {
        assert_eq!(Mailer::new(&config()).unwrap().recipients(), "admin@example.org");
        assert!(Mailer::new(&MailConfig { to: vec![], ..config() }).is_err());
        assert!(Mailer::new(&MailConfig { from: "kein mail".into(), ..config() }).is_err());
        assert_eq!(Security::parse("STARTTLS"), Some(Security::StartTls));
        assert_eq!(Security::parse("ssl"), Some(Security::Tls));
        assert_eq!(Security::parse("x"), None);
    }
}
