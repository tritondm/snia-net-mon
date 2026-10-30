//! Schleichender Anstieg (CUSUM): Ein Host lädt über viele Stunden nur *leicht* mehr hoch als sonst – zu wenig für die
//! Statistik in einem einzelnen Fenster, aber in Summe ein Datenabfluss („Low and Slow“).
//!
//! Je Host läuft eine einseitige CUSUM-Summe über die Z-Scores des Uploads gegen dasselbe Vergleichsprofil wie bei der
//! Statistik (Host- oder Gruppen-Slot):
//!
//! ```text
//! S ← max(0, S + min(z, z_threshold) − k)
//! ```
//!
//! Normales Rauschen (`z` um 0) zieht die Summe immer wieder auf 0, eine kleine, aber dauerhafte Erhöhung summiert sich
//! auf. Gemeldet wird, sobald `S ≥ h` **und** die Mehrmenge seit Beginn des Anstiegs `min_excess` erreicht. Der Z-Score
//! geht höchstens mit `z_threshold` ein: Eine einzelne Spitze meldet schon die Statistik, sie soll die Summe nicht allein
//! über die Grenze heben. Der Zustand liegt nur im Speicher (eine Summe je Host) und beginnt nach einem Neustart neu.

use std::collections::HashMap;

/// Merkmal, das beobachtet wird: der Upload (Index in [`crate::features::NAMES`]).
pub const FEATURE: usize = 0;

/// Einstellungen (`anomaly.drift*`).
#[derive(Debug, Clone)]
pub struct DriftConfig {
    pub enabled: bool,
    /// Toleranz `k`: so viele Standardabweichungen über dem Typischen zählen noch als normal
    pub k: f64,
    /// Grenze `h`: ab dieser Summe wird gemeldet
    pub h: f64,
    /// Mindest-Mehrmenge seit Beginn des Anstiegs in Bytes (Summe der Rohwerte minus Summe der typischen Werte)
    pub min_excess: f64,
}

impl Default for DriftConfig {
    fn default() -> Self {
        Self { enabled: true, k: 0.5, h: 10.0, min_excess: 250.0 * 1024.0 * 1024.0 }
    }
}

/// Laufender Anstieg eines Hosts.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct State {
    /// CUSUM-Summe `S`
    pub sum: f64,
    /// Beginn des ersten Fensters, seit dem `S` über 0 liegt
    pub since_ms: i64,
    /// Fenster seit `since_ms`
    pub windows: u32,
    /// Summe der Rohwerte bzw. der typischen Werte seit `since_ms`
    pub value: f64,
    pub typical: f64,
    /// Beginn des zuletzt eingerechneten Fensters
    last_ms: i64,
}

impl State {
    pub fn excess(&self) -> f64 {
        self.value - self.typical
    }
}

#[derive(Default)]
pub struct Tracker {
    states: HashMap<String, State>,
}

impl Tracker {
    /// Ein Fenster eines Hosts einrechnen: `z` gegen sein Vergleichsprofil, `value` und `typical` als Rohwerte. Fehlt
    /// das vorherige Fenster (Host inaktiv oder Profil noch nicht eingelernt), beginnt die Summe neu. Liefert den
    /// Zustand, wenn gemeldet werden soll.
    #[allow(clippy::too_many_arguments)]
    pub fn update(&mut self, cfg: &DriftConfig, z_cap: f64, host: &str, start_ms: i64, window_ms: i64, z: f64, value: f64, typical: f64) -> Option<State> {
        let prev = self.states.get(host).copied().filter(|s| s.last_ms == start_ms - window_ms).unwrap_or_default();
        let sum = prev.sum + z.min(z_cap) - cfg.k;
        if sum <= 0.0 {
            self.states.remove(host);
            return None;
        }
        let fresh = prev.sum == 0.0;
        let state = State {
            // nach oben begrenzt, damit ein beendeter Anstieg nicht stundenlang nachwirkt
            sum: sum.min(2.0 * cfg.h),
            since_ms: if fresh { start_ms } else { prev.since_ms },
            windows: prev.windows + 1,
            value: prev.value + value,
            typical: prev.typical + typical,
            last_ms: start_ms,
        };
        self.states.insert(host.to_string(), state);
        (state.sum >= cfg.h && state.excess() >= cfg.min_excess).then_some(state)
    }

    /// Zustände von Hosts vergessen, die seit `before_ms` kein Fenster mehr hatten.
    pub fn prune(&mut self, before_ms: i64) {
        self.states.retain(|_, s| s.last_ms >= before_ms);
    }

    /// Hosts mit laufender Summe (`S > 0`) – bei normalem Rauschen auch kurz einige.
    pub fn active(&self) -> usize {
        self.states.len()
    }

    /// Hosts, deren Summe mindestens die halbe Grenze erreicht hat: ein Anstieg, der auf eine Meldung zuläuft.
    pub fn rising(&self, h: f64) -> usize {
        self.states.values().filter(|s| s.sum >= h / 2.0).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const W: i64 = 600_000;
    const MIB: f64 = 1024.0 * 1024.0;

    #[test]
    fn noise_stays_near_zero() {
        let cfg = DriftConfig::default();
        let mut t = Tracker::default();
        // abwechselnd etwas über und unter dem Typischen, wie normales Rauschen
        for i in 0..1000 {
            let z = if i % 2 == 0 { 1.2 } else { -1.0 };
            assert!(t.update(&cfg, 4.0, "10.0.0.5", i * W, W, z, 50.0 * MIB, 20.0 * MIB).is_none());
        }
        assert!(t.states.get("10.0.0.5").is_none_or(|s| s.sum < 1.0));
    }

    #[test]
    fn small_sustained_increase_is_reported_with_its_start() {
        let cfg = DriftConfig::default();
        let mut t = Tracker::default();
        // z = 1,5: in jedem Fenster weit unter z_threshold = 4, aber dauerhaft – je Fenster +1,0
        let found: Vec<_> = (0..12).map(|i| t.update(&cfg, 4.0, "10.0.0.5", i * W, W, 1.5, 60.0 * MIB, 20.0 * MIB)).collect();
        assert!(found[..9].iter().all(Option::is_none), "erst ab S ≥ 10");
        let s = found[9].expect("nach 10 Fenstern gemeldet");
        assert_eq!((s.since_ms, s.windows), (0, 10));
        assert!((s.excess() - 400.0 * MIB).abs() < 1.0);
        assert!(found[10].is_some(), "läuft weiter, solange der Anstieg anhält");
        assert_eq!((t.active(), t.rising(cfg.h)), (1, 1));
    }

    #[test]
    fn spike_is_capped_and_small_excess_is_not_reported() {
        let cfg = DriftConfig::default();
        let mut t = Tracker::default();
        // eine riesige Spitze zählt höchstens wie z_threshold
        assert!(t.update(&cfg, 4.0, "a", 0, W, 50.0, 10_000.0 * MIB, 20.0 * MIB).is_none());
        assert_eq!(t.states["a"].sum, 3.5);
        // dauerhaft erhöht, aber nur wenige MiB mehr: keine Meldung (leises Gerät)
        let quiet = (0..50).filter_map(|i| t.update(&cfg, 4.0, "b", i * W, W, 2.0, 3.0 * MIB, 1.0 * MIB)).count();
        assert_eq!(quiet, 0);
        assert!(t.states["b"].sum <= 2.0 * cfg.h, "Summe ist begrenzt");
    }

    #[test]
    fn gap_restarts_and_prune_forgets() {
        let cfg = DriftConfig::default();
        let mut t = Tracker::default();
        for i in 0..5 {
            t.update(&cfg, 4.0, "a", i * W, W, 2.0, 0.0, 0.0);
        }
        assert_eq!(t.states["a"].windows, 5);
        // ein Fenster fehlt: neuer Anfang
        t.update(&cfg, 4.0, "a", 6 * W, W, 2.0, 0.0, 0.0);
        assert_eq!((t.states["a"].windows, t.states["a"].since_ms), (1, 6 * W));
        // Rückgang auf 0 löscht den Zustand
        t.update(&cfg, 4.0, "a", 7 * W, W, -5.0, 0.0, 0.0);
        assert_eq!(t.active(), 0);
        t.update(&cfg, 4.0, "b", 0, W, 2.0, 0.0, 0.0);
        t.prune(W);
        assert_eq!(t.active(), 0);
    }
}
