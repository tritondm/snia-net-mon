//! PCAP-Analyse: Upload einer Capture-Datei, Analyse im Hintergrund-Thread, Ergebnis in der Datenbank.
//!
//! Die hochgeladene Datei wird nur als temporäre Datei für die Dauer der Analyse gehalten und danach gelöscht.

use crate::{ApiError, ApiResult, AppState};
use axum::Json;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures::StreamExt;
use serde::Deserialize;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::AsyncWriteExt;

static UPLOAD_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Deserialize)]
pub struct UploadParams {
    name: Option<String>,
}

/// Temporäre Datei, die beim Verlassen des Gültigkeitsbereichs gelöscht wird – auch bei Fehlern und Abbrüchen.
struct TempFile(std::path::PathBuf);

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// `POST /api/pcap?name=datei.pcap` – Rohdaten der Datei als Body.
pub async fn upload(State(s): State<AppState>, Query(p): Query<UploadParams>, body: Body) -> Result<Response, ApiError> {
    let name = clean_name(p.name.as_deref().unwrap_or("upload.pcap"));
    tokio::fs::create_dir_all(&s.pcap.upload_dir).await.map_err(internal)?;
    let n = UPLOAD_COUNTER.fetch_add(1, Ordering::Relaxed);
    let temp = TempFile(s.pcap.upload_dir.join(format!("upload-{}-{n}.tmp", std::process::id())));

    // Body gestreamt in die Datei schreiben, Größe dabei begrenzen
    let mut file = tokio::fs::File::create(&temp.0).await.map_err(internal)?;
    let mut size: u64 = 0;
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| ApiError(StatusCode::BAD_REQUEST, format!("Upload abgebrochen: {e}")))?;
        size += chunk.len() as u64;
        if size > s.pcap.max_upload_bytes {
            return Err(ApiError(StatusCode::PAYLOAD_TOO_LARGE, format!("Datei größer als {} MiB", s.pcap.max_upload_bytes / 1024 / 1024)));
        }
        file.write_all(&chunk).await.map_err(internal)?;
    }
    file.flush().await.map_err(internal)?;
    drop(file);
    if size == 0 {
        return Err(ApiError(StatusCode::BAD_REQUEST, "leere Datei".into()));
    }

    let (geo, apps, path, fname) = (s.geo.clone(), s.pcap.apps.clone(), temp.0.clone(), name.clone());
    let started = std::time::Instant::now();
    let mut result = tokio::task::spawn_blocking(move || {
        let file = std::fs::File::open(&path).map_err(|e| e.to_string())?;
        pcap::analyze(file, &fname, &geo, &apps)
    })
    .await
    .map_err(internal)?
    .map_err(|msg| ApiError(StatusCode::UNPROCESSABLE_ENTITY, msg))?;
    drop(temp);

    let packets = result["total"]["packets"].as_u64().unwrap_or(0);
    let bytes = result["total"]["bytes"].as_u64().unwrap_or(0);
    result["file_size"] = size.into();
    tracing::info!(file = %name, size, packets, ms = started.elapsed().as_millis() as u64, "PCAP analysiert");
    let id = s.db.save_pcap(name, size, packets, bytes, result.to_string()).await?;
    result["id"] = id.into();
    Ok((StatusCode::CREATED, Json(result)).into_response())
}

#[derive(Deserialize)]
pub struct ListParams {
    limit: Option<u32>,
}

pub async fn list(State(s): State<AppState>, Query(p): Query<ListParams>) -> ApiResult<Vec<db::PcapSummary>> {
    Ok(Json(s.db.list_pcaps(p.limit.unwrap_or(50)).await?))
}

/// Gespeichertes Ergebnis unverändert als JSON ausliefern (wird nicht neu serialisiert).
pub async fn get(State(s): State<AppState>, Path(id): Path<i64>) -> Result<Response, ApiError> {
    let json = s.db.get_pcap(id).await?.ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "Analyse nicht gefunden".into()))?;
    Ok(([(header::CONTENT_TYPE, "application/json")], json).into_response())
}

pub async fn delete(State(s): State<AppState>, Path(id): Path<i64>) -> Result<StatusCode, ApiError> {
    if s.db.delete_pcap(id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError(StatusCode::NOT_FOUND, "Analyse nicht gefunden".into()))
    }
}

/// Nur der Dateiname, ohne Pfadanteile und Steuerzeichen, höchstens 120 Zeichen.
fn clean_name(raw: &str) -> String {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or(raw);
    let cleaned: String = base.chars().filter(|c| !c.is_control()).take(120).collect();
    if cleaned.trim().is_empty() { "upload.pcap".into() } else { cleaned }
}

fn internal(err: impl std::fmt::Display) -> ApiError {
    tracing::error!(%err, "PCAP-Upload fehlgeschlagen");
    ApiError(StatusCode::INTERNAL_SERVER_ERROR, "interner Fehler beim Upload".into())
}

#[cfg(test)]
mod tests {
    #[test]
    fn upload_names_are_sanitised() {
        assert_eq!(super::clean_name("../../etc/passwd"), "passwd");
        assert_eq!(super::clean_name("C:\\temp\\cap.pcapng"), "cap.pcapng");
        assert_eq!(super::clean_name("a\nb.pcap"), "ab.pcap");
        assert_eq!(super::clean_name(""), "upload.pcap");
    }
}
