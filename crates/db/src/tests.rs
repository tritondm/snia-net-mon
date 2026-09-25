use super::*;
use std::net::IpAddr;

fn temp_db(name: &str) -> (Database, PathBuf) {
    let dir = std::env::temp_dir().join(format!("snm-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("flows.db");
    let db = Database::open(&DbConfig { path: path.clone(), retention_hours: 72, cleanup_interval: Duration::from_secs(60) }).unwrap();
    (db, dir)
}

fn flow(ts_ms: i64, src: &str, dst: &str, dst_port: u16, bytes: u64) -> FlowRecord {
    FlowRecord {
        ts_ms,
        start_ms: ts_ms - 1000,
        src_ip: src.parse().unwrap(),
        dst_ip: dst.parse().unwrap(),
        src_port: 50000,
        dst_port,
        proto: 6,
        bytes,
        packets: 10,
        tcp_flags: 0x1b,
        in_if: 1,
        out_if: 2,
        exporter: "192.0.2.1".parse::<IpAddr>().unwrap(),
        direction: model::Direction::Out,
    }
}

async fn ingest(db: &Database, flows: Vec<FlowRecord>) {
    let (tx, rx) = mpsc::channel(4);
    let writer = db.spawn_writer(rx).unwrap();
    tx.send(Arc::new(flows)).await.unwrap();
    drop(tx);
    tokio::task::spawn_blocking(move || writer.join().unwrap()).await.unwrap();
}

#[tokio::test]
async fn retention_deletes_everything_older_than_72h_and_hides_it_from_queries() {
    let (db, dir) = temp_db("retention");
    let now = now_ms();
    let hour = HOUR_MS;
    ingest(
        &db,
        vec![
            flow(now - 80 * hour, "10.0.0.1", "1.1.1.1", 443, 100), // zu alt
            flow(now - 73 * hour, "10.0.0.1", "1.1.1.1", 443, 100), // zu alt
            flow(now - 71 * hour, "10.0.0.2", "1.1.1.1", 443, 100), // bleibt
            flow(now - 60_000, "10.0.0.3", "1.1.1.1", 443, 100),    // bleibt
        ],
    )
    .await;

    // Schon vor dem Cleanup liefern Abfragen nichts außerhalb des Fensters
    let all = db.query_flows(FlowFilter { from: Some(0), ..Default::default() }).await.unwrap();
    assert_eq!(all.len(), 2);

    assert_eq!(db.cleanup_now().await.unwrap(), 2);
    let conn = schema::open_connection(&dir.join("flows.db")).unwrap();
    let remaining: i64 = conn.query_row("SELECT COUNT(*) FROM flows", [], |r| r.get(0)).unwrap();
    assert_eq!(remaining, 2);
    let oldest: i64 = conn.query_row("SELECT MIN(ts) FROM flows", [], |r| r.get(0)).unwrap();
    assert!(oldest >= now - 72 * hour);
    assert_eq!(db.stats().await.unwrap().rows, 2);
    // Ein zweiter Lauf hat nichts mehr zu tun
    assert_eq!(db.cleanup_now().await.unwrap(), 0);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn retention_cannot_exceed_72_hours() {
    let dir = std::env::temp_dir().join(format!("snm-test-clamp-{}", std::process::id()));
    let db = Database::open(&DbConfig { path: dir.join("f.db"), retention_hours: 24 * 30, cleanup_interval: Duration::from_secs(60) }).unwrap();
    assert_eq!(db.retention_ms(), 72 * HOUR_MS);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn filters_and_aggregations() {
    let (db, dir) = temp_db("aggr");
    let now = now_ms();
    ingest(
        &db,
        vec![
            flow(now - 1000, "192.168.1.10", "1.1.1.1", 443, 5000),
            flow(now - 2000, "192.168.1.10", "9.9.9.9", 53, 100),
            flow(now - 3000, "192.168.1.11", "1.1.1.1", 443, 1000),
            flow(now - 4000, "2001:db8::10", "2606:4700::1", 443, 700),
        ],
    )
    .await;

    let by_cidr = db.query_flows(FlowFilter { ip: Some("192.168.1.0/24".into()), ..Default::default() }).await.unwrap();
    assert_eq!(by_cidr.len(), 3);
    let by_v6 = db.query_flows(FlowFilter { src: Some("2001:db8::/32".into()), ..Default::default() }).await.unwrap();
    assert_eq!(by_v6.len(), 1);
    assert_eq!(by_v6[0].dst_ip, "2606:4700::1");
    let dns = db.query_flows(FlowFilter { port: Some(53), ..Default::default() }).await.unwrap();
    assert_eq!(dns.len(), 1);
    assert!(db.query_flows(FlowFilter { ip: Some("kaputt".into()), ..Default::default() }).await.is_err());

    let talkers = db.top_talkers(FlowFilter::default()).await.unwrap();
    assert_eq!(talkers[0].ip, "1.1.1.1");
    assert_eq!(talkers[0].bytes, 6000);
    assert_eq!(talkers[1].ip, "192.168.1.10");

    let ports = db.top_ports(FlowFilter::default()).await.unwrap();
    assert_eq!((ports[0].port, ports[0].bytes), (443, 6700));
    // Antwort-Flows (Server:443 → Client:ephemer) zählen zum selben Dienst-Port
    let (db2, dir2) = temp_db("service-port");
    let mut reply = flow(now - 1000, "1.1.1.1", "192.168.1.10", 51514, 900);
    reply.src_port = 443;
    ingest(&db2, vec![reply, flow(now - 1000, "192.168.1.10", "1.1.1.1", 443, 100)]).await;
    let ports = db2.top_ports(FlowFilter::default()).await.unwrap();
    assert_eq!(ports.len(), 1);
    assert_eq!((ports[0].port, ports[0].bytes), (443, 1000));
    let _ = std::fs::remove_dir_all(dir2);

    let sankey = db.sankey(FlowFilter::default()).await.unwrap();
    assert!(sankey.nodes.iter().any(|n| n.id == "p:TCP/443" && n.kind == "service"));
    let into_443: i64 = sankey.links.iter().filter(|l| l.target == "p:TCP/443").map(|l| l.value).sum();
    assert_eq!(into_443, 6700);

    let (_step, series) = db.timeseries(FlowFilter::default(), 60).await.unwrap();
    assert_eq!(series.iter().map(|p| p.bytes).sum::<i64>(), 6800);
    // Testdaten sind alle "out" – als Upload gezählt, Download bleibt 0
    assert_eq!(series.iter().map(|p| p.bytes_out).sum::<i64>(), 6800);
    assert_eq!(series.iter().map(|p| p.bytes_in).sum::<i64>(), 0);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn direction_filter_and_summary() {
    let (db, dir) = temp_db("direction");
    let now = now_ms();
    let mut download = flow(now - 1000, "1.1.1.1", "192.168.1.10", 50000, 9000);
    download.direction = model::Direction::In;
    let mut internal = flow(now - 1000, "192.168.1.10", "192.168.10.20", 445, 500);
    internal.direction = model::Direction::Internal;
    ingest(&db, vec![flow(now - 2000, "192.168.1.10", "1.1.1.1", 443, 1000), download, internal]).await;

    let inbound = db.query_flows(FlowFilter { dir: Some("in".into()), ..Default::default() }).await.unwrap();
    assert_eq!(inbound.len(), 1);
    assert_eq!(inbound[0].direction, model::Direction::In);
    assert!(db.query_flows(FlowFilter { dir: Some("seitwärts".into()), ..Default::default() }).await.is_err());

    let summary = db.directions(FlowFilter::default()).await.unwrap();
    let bytes = |d| summary.iter().find(|s| s.direction == d).unwrap().bytes;
    assert_eq!(summary.len(), 4);
    assert_eq!((bytes(model::Direction::In), bytes(model::Direction::Out), bytes(model::Direction::Internal)), (9000, 1000, 500));
    assert_eq!(bytes(model::Direction::External), 0);

    // Top Talker nur für Downloads
    let talkers = db.top_talkers(FlowFilter { dir: Some("in".into()), ..Default::default() }).await.unwrap();
    assert_eq!(talkers.len(), 2);
    assert!(talkers.iter().all(|t| t.bytes == 9000));
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn old_database_without_direction_column_is_migrated() {
    let dir = std::env::temp_dir().join(format!("snm-test-migrate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("old.db");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE flows (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, start_ts INTEGER NOT NULL, bucket INTEGER NOT NULL,
             src_ip BLOB NOT NULL, dst_ip BLOB NOT NULL, src_port INTEGER NOT NULL, dst_port INTEGER NOT NULL, proto INTEGER NOT NULL,
             bytes INTEGER NOT NULL, packets INTEGER NOT NULL, tcp_flags INTEGER NOT NULL, in_if INTEGER NOT NULL, out_if INTEGER NOT NULL,
             exporter BLOB NOT NULL);",
        )
        .unwrap();
    }
    let db = Database::open(&DbConfig { path, retention_hours: 72, cleanup_interval: Duration::from_secs(60) }).unwrap();
    ingest(&db, vec![flow(now_ms() - 1000, "192.168.1.10", "1.1.1.1", 443, 10)]).await;
    assert_eq!(db.query_flows(FlowFilter::default()).await.unwrap()[0].direction, model::Direction::Out);
    let _ = std::fs::remove_dir_all(dir);
}
