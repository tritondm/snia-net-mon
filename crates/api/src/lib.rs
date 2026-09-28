//! HTTP-Schnittstelle: REST-API unter `/api`, WebSocket-Live-Stream unter `/api/live` und Auslieferung des gebauten
//! Frontends (Single-Page-App) für alle übrigen Pfade.

mod live;
mod pcap;

pub use live::LiveHub;

use axum::extract::DefaultBodyLimit;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get};
use axum::{Json, Router};
use collector::CollectorMetrics;
use db::{Database, DbError, FlowFilter};
use geo::{GeoInfo, GeoLookup};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::broadcast::error::RecvError;
use tower_http::services::{ServeDir, ServeFile};

#[derive(Clone)]
pub struct AppState {
    pub db: Database,
    pub metrics: Arc<CollectorMetrics>,
    pub live: LiveHub,
    /// Ist ein Token gesetzt, verlangt jede API-Anfrage `Authorization: Bearer <token>` (WebSocket/Download: `?token=`).
    pub api_token: Option<Arc<str>>,
    pub started_ms: i64,
    pub geo: Arc<GeoLookup>,
    pub pcap: PcapSettings,
}

#[derive(Clone)]
pub struct PcapSettings {
    /// Verzeichnis für temporäre Upload-Dateien (werden nach der Analyse gelöscht)
    pub upload_dir: PathBuf,
    pub max_upload_bytes: u64,
    pub apps: Arc<::pcap::AppRules>,
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
        .route("/stats/connections", get(connections))
        .route("/stats/peers", get(peers))
        .route("/stats/geo", get(geo_stats))
        .route("/pcap", get(pcap::list).post(pcap::upload).layer(DefaultBodyLimit::disable()))
        .route("/pcap/{id}", get(pcap::get).merge(delete(pcap::delete)))
        .route("/live", get(live_ws))
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
    geoip: &'static str,
    /// Erstellungsdatum der ältesten geladenen GeoIP-Datenbank (Unix-ms)
    #[serde(skip_serializing_if = "Option::is_none")]
    geoip_built_ms: Option<i64>,
    pcap_max_upload_mb: u64,
}

async fn status(State(s): State<AppState>) -> ApiResult<Status> {
    let db = s.db.stats().await?;
    Ok(Json(Status {
        started_ms: s.started_ms,
        now_ms: model::now_ms(),
        retention_hours: db.retention_hours,
        collector: s.metrics.snapshot(),
        db,
        geoip: s.geo.describe(),
        geoip_built_ms: {
            let (country, asn) = s.geo.build_epochs();
            country.into_iter().chain(asn).min().map(|secs| secs as i64 * 1000)
        },
        pcap_max_upload_mb: s.pcap.max_upload_bytes / 1024 / 1024,
    }))
}

/// Datensatz mit GeoIP-Daten für Quelle und Ziel (nur öffentliche IPs; leere Felder entfallen).
#[derive(Serialize)]
struct WithPeerGeo<T> {
    #[serde(flatten)]
    row: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    src_geo: Option<GeoInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dst_geo: Option<GeoInfo>,
}

#[derive(Serialize)]
struct WithGeo<T> {
    #[serde(flatten)]
    row: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    geo: Option<GeoInfo>,
}

async fn flows(State(s): State<AppState>, Query(f): Query<FlowFilter>) -> ApiResult<Vec<WithPeerGeo<db::FlowRow>>> {
    let rows = s.db.query_flows(f).await?;
    Ok(Json(rows.into_iter().map(|row| WithPeerGeo { src_geo: s.geo.lookup_str(&row.src_ip), dst_geo: s.geo.lookup_str(&row.dst_ip), row }).collect()))
}

async fn talkers(State(s): State<AppState>, Query(f): Query<FlowFilter>) -> ApiResult<Vec<WithGeo<db::TalkerStat>>> {
    let rows = s.db.top_talkers(f).await?;
    Ok(Json(rows.into_iter().map(|row| WithGeo { geo: s.geo.lookup_str(&row.ip), row }).collect()))
}

#[derive(Serialize, Default)]
struct GeoBucket {
    #[serde(skip_serializing_if = "Option::is_none")]
    cc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    asn: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    org: Option<String>,
    bytes: i64,
    flows: i64,
    ips: u32,
}

#[derive(Serialize)]
struct GeoStats {
    countries: Vec<GeoBucket>,
    asns: Vec<GeoBucket>,
    /// Verkehr externer IPs ohne Treffer in der GeoIP-Datenbank
    unknown_bytes: i64,
    enabled: bool,
}

/// Verkehr externer Gegenstellen nach Land und autonomem System (je IP summiert, dann gruppiert).
async fn geo_stats(State(s): State<AppState>, Query(f): Query<FlowFilter>) -> ApiResult<GeoStats> {
    let limit = f.limit.unwrap_or(10).clamp(1, 50) as usize;
    let ips = s.db.ip_totals(f, 50_000).await?;
    let mut countries: HashMap<String, GeoBucket> = HashMap::new();
    let mut asns: HashMap<u32, GeoBucket> = HashMap::new();
    let mut unknown_bytes = 0;
    for t in ips {
        let Ok(ip) = t.ip.parse() else { continue };
        if !geo::is_public(ip) {
            continue;
        }
        let g = s.geo.lookup(ip);
        if g.is_empty() {
            unknown_bytes += t.bytes;
            continue;
        }
        if let Some(cc) = &g.cc {
            let b = countries.entry(cc.clone()).or_insert_with(|| GeoBucket { cc: g.cc.clone(), country: g.country.clone(), ..Default::default() });
            (b.bytes, b.flows, b.ips) = (b.bytes + t.bytes, b.flows + t.flows, b.ips + 1);
        }
        if let Some(asn) = g.asn {
            let b = asns.entry(asn).or_insert_with(|| GeoBucket { asn: Some(asn), org: g.org.clone(), cc: g.cc.clone(), ..Default::default() });
            (b.bytes, b.flows, b.ips) = (b.bytes + t.bytes, b.flows + t.flows, b.ips + 1);
        }
    }
    let top = |mut v: Vec<GeoBucket>| {
        v.sort_by_key(|b| std::cmp::Reverse(b.bytes));
        v.truncate(limit);
        v
    };
    Ok(Json(GeoStats {
        countries: top(countries.into_values().collect()),
        asns: top(asns.into_values().collect()),
        unknown_bytes,
        enabled: s.geo.enabled(),
    }))
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

async fn connections(State(s): State<AppState>, Query(f): Query<FlowFilter>) -> ApiResult<Vec<WithPeerGeo<db::ConnectionStat>>> {
    let rows = s.db.connections(f).await?;
    Ok(Json(rows.into_iter().map(|row| WithPeerGeo { src_geo: s.geo.lookup_str(&row.src_ip), dst_geo: s.geo.lookup_str(&row.dst_ip), row }).collect()))
}

async fn peers(State(s): State<AppState>, Query(f): Query<FlowFilter>) -> ApiResult<Vec<WithPeerGeo<db::PeerStat>>> {
    let rows = s.db.peers(f).await?;
    Ok(Json(rows.into_iter().map(|row| WithPeerGeo { src_geo: s.geo.lookup_str(&row.src_ip), dst_geo: s.geo.lookup_str(&row.dst_ip), row }).collect()))
}

async fn sankey(State(s): State<AppState>, Query(f): Query<FlowFilter>) -> ApiResult<db::SankeyGraph> {
    let mut graph = s.db.sankey(f).await?;
    for node in graph.nodes.iter_mut().filter(|n| n.kind != "service") {
        node.cc = s.geo.lookup_str(&node.label).and_then(|g| g.cc);
    }
    Ok(Json(graph))
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
