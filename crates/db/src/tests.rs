use super::*;
use std::path::Path;
use std::net::IpAddr;

fn temp_db(name: &str) -> (Database, PathBuf) {
    let dir = std::env::temp_dir().join(format!("snm-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("flows.db");
    let db = Database::open(&DbConfig { path: path.clone(), retention_hours: 72, cleanup_interval: Duration::from_secs(60), secure_delete: true }).unwrap();
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
    let conn = schema::open_connection(&dir.join("flows.db"), true).unwrap();
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
    let db = Database::open(&DbConfig { path: dir.join("f.db"), retention_hours: 24 * 30, cleanup_interval: Duration::from_secs(60), secure_delete: true }).unwrap();
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

    // Verbindungen: Flows desselben 5-Tupels werden zusammengefasst, Zeitfenster schränkt ein
    ingest(&db, vec![flow(now - 500, "192.168.1.10", "1.1.1.1", 443, 2000)]).await;
    let conns = db.connections(FlowFilter::default()).await.unwrap();
    assert_eq!(conns.len(), 4);
    assert_eq!((conns[0].src_ip.as_str(), conns[0].dst_ip.as_str(), conns[0].bytes, conns[0].flows), ("192.168.1.10", "1.1.1.1", 7000, 2));
    assert!(conns[0].first_seen <= conns[0].last_seen);
    let recent = db.connections(FlowFilter { from: Some(now - 1500), to: Some(now), ..Default::default() }).await.unwrap();
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].bytes, 7000);
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
    // Ein entpacktes Archiv im alten Format wird nur gelesen und nicht umgeschrieben
    let view_path = dir.join("view.db");
    std::fs::copy(&path, &view_path).unwrap();
    let db = Database::open(&DbConfig { path: path.clone(), retention_hours: 72, cleanup_interval: Duration::from_secs(60), secure_delete: true }).unwrap();
    ingest(&db, vec![flow(now_ms() - 1000, "192.168.1.10", "1.1.1.1", 443, 10)]).await;
    assert_eq!(db.query_flows(FlowFilter::default()).await.unwrap()[0].direction, model::Direction::Out);
    // Version 3: Spalte bucket und Index auf dst_port sind entfernt
    let conn = schema::open_connection(&path, true).unwrap();
    let column = |conn: &rusqlite::Connection| -> i64 {
        conn.query_row("SELECT COUNT(*) FROM pragma_table_info('flows') WHERE name = 'bucket'", [], |r| r.get(0)).unwrap()
    };
    assert_eq!(column(&conn), 0);
    let index: i64 = conn.query_row("SELECT COUNT(*) FROM sqlite_master WHERE name = 'idx_flows_dport_ts'", [], |r| r.get(0)).unwrap();
    assert_eq!(index, 0);

    let view = Database::open_view(&view_path).unwrap();
    assert!(view.query_flows(FlowFilter { from: Some(0), ..Default::default() }).await.unwrap().is_empty());
    assert_eq!(column(&schema::open_connection(&view_path, false).unwrap()), 1);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn retention_without_secure_delete_reuses_free_pages() {
    let dir = std::env::temp_dir().join(format!("snm-test-nosecure-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let path = dir.join("flows.db");
    let db = Database::open(&DbConfig { path: path.clone(), retention_hours: 72, cleanup_interval: Duration::from_secs(60), secure_delete: false }).unwrap();
    let now = now_ms();
    let old: Vec<_> = (0..2000).map(|i| flow(now - 80 * HOUR_MS + i, "10.0.0.1", "1.1.1.1", 443, 100)).collect();
    ingest(&db, old).await;
    ingest(&db, vec![flow(now - 60_000, "10.0.0.2", "1.1.1.1", 443, 100)]).await;
    assert_eq!(db.cleanup_now().await.unwrap(), 2000);
    let conn = schema::open_connection(&path, false).unwrap();
    let secure: i64 = conn.query_row("PRAGMA secure_delete", [], |r| r.get(0)).unwrap();
    assert_eq!(secure, 0);
    let remaining: i64 = conn.query_row("SELECT COUNT(*) FROM flows", [], |r| r.get(0)).unwrap();
    assert_eq!(remaining, 1);
    assert_eq!(db.query_flows(FlowFilter { from: Some(0), ..Default::default() }).await.unwrap().len(), 1);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn pcap_analyses_are_stored_and_expire_with_retention() {
    let (db, dir) = temp_db("pcap");
    let id = db.save_pcap("mitschnitt.pcap".into(), 1234, 10, 900, r#"{"filename":"mitschnitt.pcap"}"#.into()).await.unwrap();
    let list = db.list_pcaps(20).await.unwrap();
    assert_eq!((list.len(), list[0].id, list[0].packets), (1, id, 10));
    assert_eq!(db.get_pcap(id).await.unwrap().as_deref(), Some(r#"{"filename":"mitschnitt.pcap"}"#));

    db.cleanup_before(now_ms() + 1).await.unwrap();
    assert!(db.list_pcaps(20).await.unwrap().is_empty());
    assert_eq!(db.get_pcap(id).await.unwrap(), None);
    assert!(!db.delete_pcap(id).await.unwrap());
    let _ = std::fs::remove_dir_all(dir);
}

/// Reproduzierbare Testdaten über die letzten fünf Stunden: verschiedene IPs, Dienste, Protokolle und Richtungen.
fn mixed_flows(now: i64, count: usize) -> Vec<FlowRecord> {
    let mut seed: u64 = 0x5eed;
    let mut next = move |n: u64| {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (seed >> 33) % n
    };
    let locals = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "fd00::5"];
    let remotes = ["1.1.1.1", "8.8.8.8", "2606:4700::1111"];
    (0..count)
        .map(|_| {
            let (local, remote) = (locals[next(4) as usize], remotes[next(3) as usize]);
            let service = [443, 53, 22][next(3) as usize];
            let mut f = flow(now - next(5 * HOUR_MS as u64) as i64, local, remote, service, 100 + next(100_000));
            f.src_port = 40000 + next(20000) as u16;
            f.proto = [6, 6, 17, 1][next(4) as usize];
            f.direction = model::Direction::from_u8(next(4) as u8);
            if next(2) == 0 {
                // Antwort-Flow: Server → Client
                (f.src_ip, f.dst_ip, f.src_port, f.dst_port) = (f.dst_ip, f.src_ip, f.dst_port, f.src_port);
            }
            f
        })
        .collect()
}

/// Alle Statistiken eines Filters als vergleichbarer Text (Reihenfolge bei Gleichstand normalisiert).
async fn stats_snapshot(db: &Database, filter: &FlowFilter) -> Vec<String> {
    let with_limit = |limit| FlowFilter { limit: Some(limit), ..filter.clone() };
    let mut talkers = db.ip_totals(filter.clone(), 1000).await.unwrap();
    talkers.sort_by(|a, b| a.ip.cmp(&b.ip));
    let mut ports = db.top_ports(with_limit(100)).await.unwrap();
    ports.sort_by_key(|p| (p.port, p.proto));
    let mut protocols = db.protocols(filter.clone()).await.unwrap();
    protocols.sort_by_key(|p| p.proto);
    let mut peers = db.peers(with_limit(5000)).await.unwrap();
    peers.sort_by(|a, b| (&a.src_ip, &a.dst_ip, a.proto, a.port).cmp(&(&b.src_ip, &b.dst_ip, b.proto, b.port)));
    let mut sankey = db.sankey(with_limit(200)).await.unwrap();
    sankey.nodes.sort_by(|a, b| a.id.cmp(&b.id));
    sankey.links.sort_by(|a, b| (&a.source, &a.target).cmp(&(&b.source, &b.target)));
    vec![
        format!("{talkers:?}"),
        format!("{ports:?}"),
        format!("{protocols:?}"),
        format!("{:?}", db.directions(filter.clone()).await.unwrap()),
        format!("{peers:?}"),
        format!("{sankey:?}"),
        format!("{:?}", db.timeseries(filter.clone(), 40).await.unwrap()),
        format!("{:?}", db.timeseries(filter.clone(), 400).await.unwrap()),
        format!("{:?}", db.timeseries(filter.clone(), 4).await.unwrap()),
    ]
}

fn test_windows(now: i64) -> Vec<FlowFilter> {
    let window = |from: i64, to: i64, dir: Option<&str>| FlowFilter { from: Some(from), to: Some(to), dir: dir.map(Into::into), ..Default::default() };
    vec![
        window(now - 4 * HOUR_MS - 123_457, now - 17, None),
        window(now - 4 * HOUR_MS - 123_457, now - 17, Some("in")),
        window(now - 30 * 60_000 + 5, now, None),
        // 71 h statt 72 h: an der Retention-Grenze würde `from` mit der Uhr wandern
        window(now - 71 * HOUR_MS - 999, now, Some("out")),
        window(now - 90_000, now - 30_000, None),
        FlowFilter { from: Some(now - 3 * HOUR_MS), to: Some(now), ip: Some("192.168.1.0/24".into()), ..Default::default() },
    ]
}

#[tokio::test]
async fn aggregated_statistics_match_raw_flows() {
    let (db, dir) = temp_db("rollup");
    let now = now_ms();
    // In mehreren Batches, damit Upserts in bestehende Aggregat-Zeilen laufen
    let flows = mixed_flows(now, 3000);
    for chunk in flows.chunks(700) {
        ingest(&db, chunk.to_vec()).await;
    }
    let conn = schema::open_connection(&dir.join("flows.db"), true).unwrap();
    let hours: i64 = conn.query_row("SELECT COUNT(*) FROM agg_svc_1h", [], |r| r.get(0)).unwrap();
    assert!(hours > 0, "Aggregate wurden nicht geschrieben");

    for filter in test_windows(now) {
        db.set_rollups(true);
        let aggregated = stats_snapshot(&db, &filter).await;
        db.set_rollups(false);
        let raw = stats_snapshot(&db, &filter).await;
        for (a, r) in aggregated.iter().zip(&raw) {
            assert_eq!(a, r, "Abweichung für {filter:?}");
        }
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn existing_database_gets_aggregates_backfilled() {
    let (db, dir) = temp_db("backfill");
    let now = now_ms();
    ingest(&db, mixed_flows(now, 1500)).await;
    db.set_rollups(false);
    let filter = test_windows(now).remove(0);
    let raw = stats_snapshot(&db, &filter).await;
    drop(db);
    {
        // Stand vor der Voraggregation herstellen
        let conn = schema::open_connection(&dir.join("flows.db"), true).unwrap();
        for table in rollup::tables() {
            conn.execute_batch(&format!("DROP TABLE {table};")).unwrap();
        }
        conn.execute_batch("PRAGMA user_version = 1;").unwrap();
    }
    let db = Database::open(&DbConfig { path: dir.join("flows.db"), retention_hours: 72, cleanup_interval: Duration::from_secs(60), secure_delete: true }).unwrap();
    assert_eq!(stats_snapshot(&db, &filter).await, raw);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn retention_also_removes_aggregates() {
    let (db, dir) = temp_db("rollup-retention");
    let now = now_ms();
    ingest(&db, vec![flow(now - 80 * HOUR_MS, "10.0.0.1", "1.1.1.1", 443, 100), flow(now - 60_000, "10.0.0.2", "1.1.1.1", 443, 100)]).await;
    db.cleanup_now().await.unwrap();
    let conn = schema::open_connection(&dir.join("flows.db"), true).unwrap();
    let floor = now - 72 * HOUR_MS;
    for table in rollup::tables() {
        let old: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {table} WHERE t < ?1"), [floor], |r| r.get(0)).unwrap();
        let recent: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0)).unwrap();
        assert_eq!(old, 0, "{table}");
        assert!(recent > 0, "{table}");
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// Lastprobe: `cargo test -p db --release -- --ignored bench --nocapture` (Anzahl per `BENCH_FLOWS`, Standard 3,6 Mio. = 1 h bei 1000 Flows/s).
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn bench_statistics_with_and_without_aggregates() {
    let count: usize = std::env::var("BENCH_FLOWS").ok().and_then(|v| v.parse().ok()).unwrap_or(3_600_000);
    let (db, dir) = temp_db("bench");
    let now = now_ms();
    let mut seed: u64 = 7;
    let mut next = move |n: u64| {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (seed >> 33) % n
    };
    let started = std::time::Instant::now();
    let (tx, rx) = mpsc::channel(64);
    let writer = db.spawn_writer(rx).unwrap();
    let span = HOUR_MS as u64;
    for chunk_start in (0..count).step_by(10_000) {
        let batch: Vec<FlowRecord> = (chunk_start..(chunk_start + 10_000).min(count))
            .map(|i| {
                // Heimnetz-ähnlich: 60 Geräte, Gegenstellen log-gleichverteilt (wenige große Dienste, lange Liste kleiner);
                // jede Verbindung ergibt wie bei softflowd einen Anfrage- (out) und einen Antwort-Flow (in)
                let local = format!("192.168.1.{}", 2 + next(60));
                let r = (20_000f64.powf(next(1_000_000) as f64 / 1_000_000.0)) as u64;
                let remote = format!("{}.{}.{}.{}", 1 + r % 200, (r / 200) % 250, 7, 1 + r % 250);
                let service = [443, 443, 443, 443, 80, 53, 853, 22][next(8) as usize];
                let mut f = flow(now - span as i64 + (i as u64 * span / count as u64) as i64, &local, &remote, service, 60 + next(2_000_000));
                f.src_port = 1024 + next(60000) as u16;
                f.direction = model::Direction::Out;
                if i % 2 == 1 {
                    (f.src_ip, f.dst_ip, f.src_port, f.dst_port) = (f.dst_ip, f.src_ip, f.dst_port, f.src_port);
                    f.direction = model::Direction::In;
                }
                f
            })
            .collect();
        tx.send(Arc::new(batch)).await.unwrap();
    }
    drop(tx);
    tokio::task::spawn_blocking(move || writer.join().unwrap()).await.unwrap();
    let path = dir.join("flows.db");
    let size = std::fs::metadata(&path).unwrap().len() + std::fs::metadata(dir.join("flows.db-wal")).map(|m| m.len()).unwrap_or(0);
    println!("{count} Flows geschrieben in {:.1?} ({:.0} Flows/s), Datei {} MiB", started.elapsed(), count as f64 / started.elapsed().as_secs_f64(), size >> 20);
    let conn = schema::open_connection(&path, true).unwrap();
    for table in rollup::tables() {
        let n: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0)).unwrap();
        println!("  {table}: {n} Zeilen");
    }

    let filter = FlowFilter { from: Some(now - HOUR_MS), to: Some(now), ..Default::default() };
    for rollups in [false, true] {
        db.set_rollups(rollups);
        println!("{}:", if rollups { "mit Aggregaten" } else { "nur Rohdaten" });
        macro_rules! time {
            ($name:literal, $e:expr) => {{
                let t = std::time::Instant::now();
                $e.await.unwrap();
                println!("  {:<12} {:>8.1?}", $name, t.elapsed());
            }};
        }
        time!("talkers", db.top_talkers(FlowFilter { limit: Some(10), ..filter.clone() }));
        time!("geo (ips)", db.ip_totals(filter.clone(), 50_000));
        time!("ports", db.top_ports(filter.clone()));
        time!("protokolle", db.protocols(filter.clone()));
        time!("richtungen", db.directions(filter.clone()));
        time!("zeitreihe", db.timeseries(filter.clone(), 120));
        time!("sankey", db.sankey(filter.clone()));
        time!("peers", db.peers(FlowFilter { limit: Some(2000), ..filter.clone() }));
    }
    let _ = std::fs::remove_dir_all(dir);
}

fn history_config(dir: &Path, max_bytes: u64, retention_days: u64) -> HistoryConfig {
    HistoryConfig {
        path: dir.join("history.db"),
        max_bytes,
        archive_dir: dir.join("archive"),
        archive_retention: Duration::from_secs(retention_days * 86_400),
        compression_level: 3,
        secure_delete: true,
    }
}

#[tokio::test]
async fn history_takes_over_flows_in_steps_with_exact_aggregates() {
    let (live, dir) = temp_db("history-steps");
    let history = History::open(history_config(&dir, u64::MAX, 90)).unwrap();
    let now = now_ms();
    for chunk in mixed_flows(now, 3000).chunks(700) {
        ingest(&live, chunk.to_vec()).await;
    }
    live.set_rollups(false);
    let mut expected = Vec::new();
    for filter in test_windows(now) {
        expected.push(stats_snapshot(&live, &filter).await);
    }

    // In mehreren Schritten verschieben – auch mitten in einer Stunde, wie es der Retention-Task tut
    let minute = |ts: i64| ts.div_euclid(MINUTE_MS) * MINUTE_MS;
    let mut moved = 0;
    for cutoff in [minute(now - 3 * HOUR_MS - 17 * MINUTE_MS), minute(now - HOUR_MS + 5 * MINUTE_MS), minute(now) + MINUTE_MS] {
        let path = live.path().to_path_buf();
        let h = history.clone();
        moved += tokio::task::spawn_blocking(move || h.absorb(&path, cutoff)).await.unwrap().unwrap();
        live.cleanup_before(cutoff).await.unwrap();
        // Wiederholung (z. B. nach Absturz zwischen Kopieren und Löschen) kopiert nichts doppelt
        let path = live.path().to_path_buf();
        let h = history.clone();
        assert_eq!(tokio::task::spawn_blocking(move || h.absorb(&path, cutoff)).await.unwrap().unwrap(), 0);
    }
    assert_eq!(moved, 3000);
    assert!(live.query_flows(FlowFilter { from: Some(0), ..Default::default() }).await.unwrap().is_empty());

    let stored = history.current().unwrap();
    assert_eq!(stored.query_flows(FlowFilter { from: Some(0), limit: Some(5000), ..Default::default() }).await.unwrap().len(), 3000);
    for (filter, expected) in test_windows(now).into_iter().zip(expected) {
        stored.set_rollups(true);
        assert_eq!(stats_snapshot(&stored, &filter).await, expected, "Aggregate der Historie weichen ab für {filter:?}");
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn history_rotates_into_compressed_archive_that_can_be_opened_and_expires() {
    let dir = std::env::temp_dir().join(format!("snm-test-archive-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let live = Database::open(&DbConfig { path: dir.join("flows.db"), retention_hours: 48, cleanup_interval: Duration::from_secs(60), secure_delete: true }).unwrap();
    // max_bytes = 1: jede nicht leere Historie wird bei der Wartung rotiert
    let history = History::open(history_config(&dir, 1, 90)).unwrap();
    let now = now_ms();
    ingest(
        &live,
        vec![
            flow(now - 60 * HOUR_MS, "10.0.0.1", "1.1.1.1", 443, 100),
            flow(now - 49 * HOUR_MS, "10.0.0.2", "1.1.1.1", 443, 200),
            flow(now - HOUR_MS, "10.0.0.3", "1.1.1.1", 443, 300), // bleibt live
        ],
    )
    .await;
    assert_eq!(live.move_to_history(&history).await.unwrap(), 2);
    assert_eq!(live.query_flows(FlowFilter { from: Some(0), ..Default::default() }).await.unwrap().len(), 1);
    assert_eq!(history.current().unwrap().query_flows(FlowFilter { from: Some(0), ..Default::default() }).await.unwrap().len(), 2);

    history.maintain().await;
    let mut archives = Vec::new();
    for _ in 0..200 {
        archives = history.archives().unwrap();
        if !archives.is_empty() && !history.status().await.unwrap().compressing {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(archives.len(), 1, "kein Archiv angelegt");
    let archive = &archives[0];
    assert_eq!(archive.state, "packed");
    assert_eq!(archive.from_ms, (now - 60 * HOUR_MS) / 1000 * 1000);
    assert!(!dir.join("history.db.rotating").exists());
    // Die neue Historie ist leer und setzt an der alten Grenze fort
    assert!(history.current().unwrap().query_flows(FlowFilter { from: Some(0), ..Default::default() }).await.unwrap().is_empty());
    assert_eq!(live.move_to_history(&history).await.unwrap(), 0);

    assert!(matches!(history.archive(&archive.name), Err(DbError::Unavailable(_))));
    assert!(history.open_archive("../history.db").is_err());
    history.open_archive(&archive.name).unwrap();
    let mut opened = None;
    for _ in 0..200 {
        if let Ok(db) = history.archive(&archive.name) {
            opened = Some(db);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let opened = opened.expect("Archiv wurde nicht entpackt");
    let rows = opened.query_flows(FlowFilter { from: Some(0), ..Default::default() }).await.unwrap();
    assert_eq!(rows.iter().map(|r| r.bytes).sum::<i64>(), 300);
    assert_eq!(history.archives().unwrap()[0].state, "ready");
    drop(opened);

    // Abgelaufen: Aufbewahrung 0 Tage
    drop(history);
    let history = History::open(history_config(&dir, u64::MAX, 0)).unwrap();
    history.maintain().await;
    assert!(history.archives().unwrap().is_empty());
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn writer_retries_when_database_stays_locked_longer_than_busy_timeout() {
    let (db, dir) = temp_db("locked");
    // Eine andere Verbindung hält die Schreibsperre länger als das Busy-Timeout von 10 s (wie ein langsames DELETE)
    let blocker = schema::open_connection(&dir.join("flows.db"), true).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(12));
        blocker.execute_batch("COMMIT").unwrap();
    });
    ingest(&db, vec![flow(now_ms() - 60_000, "10.0.0.1", "1.1.1.1", 443, 100)]).await;
    release.join().unwrap();
    let all = db.query_flows(FlowFilter { from: Some(0), ..Default::default() }).await.unwrap();
    assert_eq!(all.len(), 1, "Flow darf trotz Sperre nicht verloren gehen");
    let _ = std::fs::remove_dir_all(dir);
}

/// Lastprobe Schreiben + Retention wie im Betrieb (viele kleine Cleanup-Schritte):
/// `cargo test -p db --release -- --ignored bench_cleanup --nocapture` (Anzahl per `BENCH_FLOWS`, Standard 1 Mio.)
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn bench_cleanup_with_and_without_secure_delete() {
    let count: usize = std::env::var("BENCH_FLOWS").ok().and_then(|v| v.parse().ok()).unwrap_or(1_000_000);
    const STEPS: i64 = 40;
    for secure_delete in [true, false] {
        let dir = std::env::temp_dir().join(format!("snm-bench-cleanup-{secure_delete}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db = Database::open(&DbConfig { path: dir.join("flows.db"), retention_hours: 72, cleanup_interval: Duration::from_secs(60), secure_delete }).unwrap();
        // Gleichmäßig über eine Stunde verteilt, beginnend vor zwei Stunden
        let base = now_ms() - 2 * HOUR_MS;
        let started = Instant::now();
        let (tx, rx) = mpsc::channel(64);
        let writer = db.spawn_writer(rx).unwrap();
        for chunk_start in (0..count).step_by(10_000) {
            let batch: Vec<FlowRecord> = (chunk_start..(chunk_start + 10_000).min(count))
                .map(|i| {
                    let ts = base + (i as i64 * HOUR_MS / count as i64);
                    let mut f = flow(ts, &format!("192.168.1.{}", i % 200), &format!("1.{}.{}.1", i % 250, (i / 250) % 250), 443, 1000);
                    f.src_port = 1024 + (i % 60000) as u16;
                    f
                })
                .collect();
            tx.send(Arc::new(batch)).await.unwrap();
        }
        drop(tx);
        tokio::task::spawn_blocking(move || writer.join().unwrap()).await.unwrap();
        let written = started.elapsed();
        // Die ältere Hälfte in kleinen Schritten löschen, wie der minütliche Retention-Task
        let t = Instant::now();
        let mut deleted = 0;
        for step in 1..=STEPS {
            deleted += db.cleanup_before(base + step * HOUR_MS / 2 / STEPS).await.unwrap();
        }
        println!(
            "secure_delete={secure_delete:<5}  schreiben {count} Flows: {written:>7.1?} ({:.0}/s)   cleanup {deleted} Flows in {STEPS} Schritten: {:>7.1?}",
            count as f64 / written.as_secs_f64(),
            t.elapsed(),
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
