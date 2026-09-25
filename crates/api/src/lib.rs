//! HTTP-Schnittstelle: REST-API unter `/api`, WebSocket-Live-Stream unter `/api/live` und Auslieferung des gebauten
//! Frontends (Single-Page-App) für alle übrigen Pfade.

mod live;

pub use live::LiveHub;

use axum::body::Body;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use collector::CollectorMetrics;
use db::{Database, DbError, FlowFilter};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::broadcast::error::RecvError;
use tower_http::services::{ServeDir, ServeFile};
use tracer::{TraceError, TraceRequest, Tracer};

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub tracer: Tracer,
    pub metrics: Arc<CollectorMetrics>,
    pub live: LiveHub,
    /// Ist ein Token gesetzt, verlangt jede API-Anfrage `Authorization: Bearer <token>` (WebSocket/Download: `?token=`).
    pub api_token: Option<Arc<str>>,
    pub started_ms: i64,
}

pub fn router(state: AppState, frontend_dir: PathBuf) -> Router {
    let api = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/status", get(status))
        .route("/flows", get(flows))
        .route("/stats/talkers", get(talkers))
        .route("/stats/ports", get(ports))
        .route("/stats/protocols", get(protocols))
        .route("/stats/directions", get(directions))
        .route("/stats/timeseries", get(timeseries))
        .route("/stats/sankey", get(sankey))
        .route("/live", get(live_ws))
        .route("/traces", get(list_traces).post(start_trace))
        .route("/traces/{id}", get(get_trace).delete(delete_trace))
        .route("/traces/{id}/stop", post(stop_trace))
        .route("/traces/{id}/pcap", get(download_pcap))
        .route("/traces/{id}/packets", get(trace_packets))
        .layer(middleware::from_fn_with_state(state.clone(), require_token))
        .with_state(state);

    let index = frontend_dir.join("index.html");
    Router::new()
        .nest("/api", api)
        .fallback_service(ServeDir::new(&frontend_dir).fallback(ServeFile::new(index)))
        .layer(tower_http::trace::TraceLayer::new_for_http())
}

// ------------------------------------------------------------------------------------------------------------ Fehler

pub struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}

impl From<DbError> for ApiError {
    fn from(err: DbError) -> Self {
        match err {
            DbError::InvalidFilter(msg) => ApiError(StatusCode::BAD_REQUEST, msg),
            other => {
                tracing::error!(err = %other, "Datenbankfehler");
                ApiError(StatusCode::INTERNAL_SERVER_ERROR, "Datenbankfehler".into())
            }
        }
    }
}

impl From<TraceError> for ApiError {
    fn from(err: TraceError) -> Self {
        let status = match &err {
            TraceError::Invalid(_) => StatusCode::BAD_REQUEST,
            TraceError::NotFound => StatusCode::NOT_FOUND,
            TraceError::TooMany(_) => StatusCode::TOO_MANY_REQUESTS,
            TraceError::Io(_) | TraceError::Pcap(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        ApiError(status, err.to_string())
    }
}

type ApiResult<T> = Result<Json<T>, ApiError>;

// ------------------------------------------------------------------------------------------------ Authentifizierung

async fn require_token(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let Some(expected) = state.api_token.as_deref() else {
        return next.run(request).await;
    };
    let bearer = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let query = request.uri().query().and_then(|q| {
        q.split('&').find_map(|pair| pair.strip_prefix("token="))
    });
    let path = request.uri().path();
    let ok = path == "/health" || [bearer, query].into_iter().flatten().any(|t| constant_time_eq(t.as_bytes(), expected.as_bytes()));
    if ok {
        next.run(request).await
    } else {
        ApiError(StatusCode::UNAUTHORIZED, "API-Token fehlt oder ist falsch".into()).into_response()
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ------------------------------------------------------------------------------------------------------ Endpunkte

#[derive(Serialize)]
struct Status {
    started_ms: i64,
    now_ms: i64,
    retention_hours: u64,
    collector: collector::MetricsSnapshot,
    db: db::DbStats,
    tracer_backend: &'static str,
}

async fn status(State(s): State<AppState>) -> ApiResult<Status> {
    let db = s.db.stats().await?;
    Ok(Json(Status {
        started_ms: s.started_ms,
        now_ms: model::now_ms(),
        retention_hours: db.retention_hours,
        collector: s.metrics.snapshot(),
        db,
        tracer_backend: s.tracer.backend_name(),
    }))
}

async fn flows(State(s): State<AppState>, Query(f): Query<FlowFilter>) -> ApiResult<Vec<db::FlowRow>> {
    Ok(Json(s.db.query_flows(f).await?))
}

async fn talkers(State(s): State<AppState>, Query(f): Query<FlowFilter>) -> ApiResult<Vec<db::TalkerStat>> {
    Ok(Json(s.db.top_talkers(f).await?))
}

async fn ports(State(s): State<AppState>, Query(f): Query<FlowFilter>) -> ApiResult<Vec<db::PortStat>> {
    Ok(Json(s.db.top_ports(f).await?))
}

async fn protocols(State(s): State<AppState>, Query(f): Query<FlowFilter>) -> ApiResult<Vec<db::ProtocolStat>> {
    Ok(Json(s.db.protocols(f).await?))
}

async fn directions(State(s): State<AppState>, Query(f): Query<FlowFilter>) -> ApiResult<Vec<db::DirectionStat>> {
    Ok(Json(s.db.directions(f).await?))
}

/// Zusätzlicher Parameter der Zeitreihe. Bewusst getrennt von `FlowFilter` statt `#[serde(flatten)]`:
/// flatten reicht Query-Werte als Strings weiter, Zahlenfelder würden dann nicht mehr erkannt.
#[derive(Deserialize)]
struct SeriesParams {
    points: Option<u32>,
}

#[derive(Serialize)]
struct Series {
    step_ms: i64,
    points: Vec<db::TimePoint>,
}

async fn timeseries(State(s): State<AppState>, Query(f): Query<FlowFilter>, Query(p): Query<SeriesParams>) -> ApiResult<Series> {
    let (step_ms, points) = s.db.timeseries(f, p.points.unwrap_or(120)).await?;
    Ok(Json(Series { step_ms, points }))
}

async fn sankey(State(s): State<AppState>, Query(f): Query<FlowFilter>) -> ApiResult<db::SankeyGraph> {
    Ok(Json(s.db.sankey(f).await?))
}

async fn live_ws(State(s): State<AppState>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |socket| live_session(socket, s.live))
}

async fn live_session(mut socket: WebSocket, hub: LiveHub) {
    let mut rx = hub.subscribe();
    if socket.send(Message::Text(hub.history_message().into())).await.is_err() {
        return;
    }
    loop {
        tokio::select! {
            msg = rx.recv() => match msg {
                Ok(json) => {
                    if socket.send(Message::Text((&*json).into())).await.is_err() {
                        return;
                    }
                }
                // Langsamer Client: verpasste Ticks einfach auslassen
                Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => return,
            },
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return,
                _ => {}
            },
        }
    }
}

async fn list_traces(State(s): State<AppState>) -> Json<Vec<tracer::TraceInfo>> {
    Json(s.tracer.list())
}

async fn start_trace(State(s): State<AppState>, Json(request): Json<TraceRequest>) -> Result<(StatusCode, Json<tracer::TraceInfo>), ApiError> {
    let tracer = s.tracer.clone();
    let info = tokio::task::spawn_blocking(move || tracer.start(request))
        .await
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "Task abgebrochen".into()))??;
    Ok((StatusCode::CREATED, Json(info)))
}

async fn get_trace(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult<tracer::TraceInfo> {
    Ok(Json(s.tracer.get(&id)?))
}

async fn stop_trace(State(s): State<AppState>, Path(id): Path<String>) -> ApiResult<tracer::TraceInfo> {
    Ok(Json(s.tracer.stop(&id)?))
}

async fn delete_trace(State(s): State<AppState>, Path(id): Path<String>) -> Result<StatusCode, ApiError> {
    s.tracer.delete(&id)?;
    Ok(StatusCode::NO_CONTENT)
}

/// PCAP-Datei als Stream (funktioniert auch während eines laufenden Traces – liefert den bisherigen Stand).
async fn download_pcap(State(s): State<AppState>, Path(id): Path<String>) -> Result<Response, ApiError> {
    let path = s.tracer.pcap_path(&id)?;
    let file = tokio::fs::File::open(&path).await.map_err(|_| ApiError(StatusCode::NOT_FOUND, "PCAP-Datei nicht vorhanden".into()))?;
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/vnd.tcpdump.pcap"));
    let disposition = format!("attachment; filename=\"trace-{id}.pcap\"");
    headers.insert(header::CONTENT_DISPOSITION, HeaderValue::from_str(&disposition).unwrap_or(HeaderValue::from_static("attachment")));
    let body = Body::from_stream(tokio_util::io::ReaderStream::new(file));
    Ok((headers, body).into_response())
}

#[derive(Deserialize)]
struct PageParams {
    offset: Option<usize>,
    limit: Option<usize>,
}

async fn trace_packets(State(s): State<AppState>, Path(id): Path<String>, Query(p): Query<PageParams>) -> ApiResult<tracer::pcap::PacketPage> {
    let tracer = s.tracer.clone();
    let page = tokio::task::spawn_blocking(move || tracer.packets(&id, p.offset.unwrap_or(0), p.limit.unwrap_or(200)))
        .await
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "Task abgebrochen".into()))??;
    Ok(Json(page))
}
