//! Benachrichtigungen an die Admins.
//!
//! * [`mail`] – SMTP-Versand (STARTTLS, TLS oder unverschlüsselt im LAN)
//! * [`upload`] – erkennt Verbindungen, die mehr als eine Schwelle nach extern hochladen, und meldet sie einmal per Mail

pub mod mail;
pub mod upload;

pub use mail::{MailConfig, Mailer, Security};
pub use upload::{UploadAlertConfig, UploadTracker, spawn_upload_watch};
