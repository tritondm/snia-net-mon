//! Statistische Baseline (Variante 1): gleitender Mittelwert und gleitende Varianz (EWMA) je Netzgruppe, Zeit-Slot und
//! Merkmal, auf logarithmierten Werten.
//!
//! * **Gruppe statt Host:** Mit DHCP wechseln Adressen den Rechner. Die Baseline beschreibt deshalb den *typischen Host*
//!   einer Gruppe (Subnetz oder eigener Bereich aus `anomaly.groups`); jede Host-Messung ist eine Stichprobe davon.
//! * **Host-Profile:** In Netzen mit festen Adressen bekommt zusätzlich jeder Host ein eigenes Profil (48 Slots:
//!   Werktag/Wochenende × Stunde). Es hat Vorrang, sobald es eingelernt ist; bis dahin gilt das Gruppenprofil.
//! * **Slots:** 168 Wochen-Slots (Wochentag × Stunde, Ortszeit) und als Rückfall 24 Tages-Slots (nur Stunde). Ein
//!   Wochen-Slot wird verwendet, sobald er genug Stichproben hat – vorher der Tages-Slot.
//! * **Log-Skala:** Verkehr ist stark schief verteilt. Auf `ln(1 + x)` ist ein Z-Score von 4 bei der Mindest-
//!   Standardabweichung [`MIN_STD`] ein Faktor von gut 7 über dem Typischen.
//! * **Schutz vor Vergiftung:** Ist ein Slot eingelernt, fließen Ausreißer nur bis `Mittelwert + 3σ` ein.

use crate::features::FEATURES;
use std::collections::{HashMap, HashSet};

/// Stichproben, ab denen ein Slot als eingelernt gilt.
pub const MIN_SAMPLES: f64 = 30.0;
/// Kleinste Lernrate: Gedächtnis von rund 500 Stichproben je Slot.
const ALPHA_MIN: f64 = 0.002;
/// Untergrenze der Standardabweichung (Log-Skala), damit sehr gleichförmige Slots nicht bei jeder Kleinigkeit anschlagen.
pub const MIN_STD: f64 = 0.5;
pub const WEEK_SLOTS: u16 = 168;
const DAY_SLOT_BASE: u16 = WEEK_SLOTS;
/// Host-Slots: 192 + Stunde (Werktag) bzw. 192 + 24 + Stunde (Wochenende)
const HOST_SLOT_BASE: u16 = DAY_SLOT_BASE + 24;

fn host_slot(week_slot: u16) -> u16 {
    let weekend = week_slot / 24 >= 5;
    HOST_SLOT_BASE + if weekend { 24 } else { 0 } + week_slot % 24
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Stat {
    pub n: f64,
    pub mean: f64,
    pub var: f64,
}

impl Stat {
    pub fn update(&mut self, x: f64) {
        self.n += 1.0;
        let alpha = (1.0 / self.n).max(ALPHA_MIN);
        let diff = x - self.mean;
        let incr = alpha * diff;
        self.mean += incr;
        self.var = (1.0 - alpha) * (self.var + diff * incr);
    }

    pub fn std(&self) -> f64 {
        self.var.max(0.0).sqrt().max(MIN_STD)
    }

    pub fn z(&self, x: f64) -> f64 {
        (x - self.mean) / self.std()
    }
}

pub type Profile = [Stat; FEATURES];

/// Welcher Slot als Vergleich diente.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotKind {
    Host,
    Week,
    Day,
}

impl SlotKind {
    pub fn name(self) -> &'static str {
        match self {
            SlotKind::Host => "host",
            SlotKind::Week => "gruppe wochentag+stunde",
            SlotKind::Day => "gruppe stunde",
        }
    }
}

#[derive(Default)]
pub struct Baselines {
    profiles: HashMap<(String, u16), Profile>,
    dirty: HashSet<(String, u16)>,
}

impl Baselines {
    pub fn from_profiles(profiles: HashMap<(String, u16), Profile>) -> Self {
        Self { profiles, dirty: HashSet::new() }
    }

    /// Vergleichsprofil für einen Wochen-Slot (0 … 167): das Host-Profil (falls `host` gesetzt und eingelernt), sonst
    /// der Wochen-Slot der Gruppe, sonst ihr Tages-Slot derselben Stunde, sonst keines.
    pub fn reference(&self, group: &str, host: Option<&str>, week_slot: u16) -> Option<(SlotKind, &Profile)> {
        let ready = |key: &str, slot: u16| self.profiles.get(&(key.to_string(), slot)).filter(|p| p[0].n >= MIN_SAMPLES);
        host.and_then(|h| ready(h, host_slot(week_slot)))
            .map(|p| (SlotKind::Host, p))
            .or_else(|| ready(group, week_slot).map(|p| (SlotKind::Week, p)))
            .or_else(|| ready(group, DAY_SLOT_BASE + week_slot % 24).map(|p| (SlotKind::Day, p)))
    }

    /// Stichprobe (Log-Werte) in den Wochen- und den Tages-Slot der Gruppe und ggf. ins Host-Profil einrechnen.
    pub fn update(&mut self, group: &str, host: Option<&str>, week_slot: u16, x: &[f64; FEATURES]) {
        let mut keys = vec![(group, week_slot), (group, DAY_SLOT_BASE + week_slot % 24)];
        if let Some(host) = host {
            keys.push((host, host_slot(week_slot)));
        }
        for (name, slot) in keys {
            let key = (name.to_string(), slot);
            let profile = self.profiles.entry(key.clone()).or_default();
            for (stat, &value) in profile.iter_mut().zip(x) {
                let value = if stat.n >= MIN_SAMPLES { value.min(stat.mean + 3.0 * stat.std()) } else { value };
                stat.update(value);
            }
            self.dirty.insert(key);
        }
    }

    /// Geänderte Profile seit dem letzten Aufruf (zum Speichern).
    pub fn take_dirty(&mut self) -> Vec<((String, u16), Profile)> {
        self.dirty.drain().filter_map(|key| self.profiles.get(&key).map(|p| (key, *p))).collect()
    }

    pub fn groups(&self) -> usize {
        self.profiles.keys().filter(|(_, slot)| *slot < HOST_SLOT_BASE).map(|(g, _)| g).collect::<HashSet<_>>().len()
    }

    pub fn hosts(&self) -> usize {
        self.profiles.keys().filter(|(_, slot)| *slot >= HOST_SLOT_BASE).map(|(h, _)| h).collect::<HashSet<_>>().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ewma_matches_mean_and_variance_while_learning() {
        let mut s = Stat::default();
        for x in [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0] {
            s.update(x);
        }
        assert!((s.mean - 5.0).abs() < 1e-9);
        assert!((s.var - 4.0).abs() < 1e-9, "Populationsvarianz, war {}", s.var);
        assert!((s.z(9.0) - 2.0).abs() < 1e-9);
        // sehr gleichförmige Werte: Mindest-Standardabweichung greift
        let mut flat = Stat::default();
        (0..100).for_each(|_| flat.update(3.0));
        assert_eq!(flat.std(), MIN_STD);
    }

    #[test]
    fn week_slot_is_preferred_once_learned_and_outliers_are_clipped() {
        let mut b = Baselines::default();
        let x = [10.0; FEATURES];
        // Montag 8 Uhr = Slot 8; Dienstag 8 Uhr = Slot 32 teilt sich den Tages-Slot
        for _ in 0..20 {
            b.update("10.0.0.0/24", None, 8, &x);
            b.update("10.0.0.0/24", None, 32, &x);
        }
        assert_eq!(b.reference("10.0.0.0/24", None, 8).map(|r| r.0), Some(SlotKind::Day), "Tages-Slot hat schon 40 Stichproben");
        for _ in 0..10 {
            b.update("10.0.0.0/24", None, 8, &x);
        }
        assert_eq!(b.reference("10.0.0.0/24", None, 8).map(|r| r.0), Some(SlotKind::Week));
        assert!(b.reference("10.0.1.0/24", None, 8).is_none());

        b.update("10.0.0.0/24", None, 8, &[1000.0; FEATURES]);
        let (_, p) = b.reference("10.0.0.0/24", None, 8).unwrap();
        assert!(p[0].mean < 10.1, "Ausreißer darf die Baseline kaum verschieben: {}", p[0].mean);
        assert_eq!(b.take_dirty().len(), 3, "Wochen-Slots 8 und 32, gemeinsamer Tages-Slot");
        assert!(b.take_dirty().is_empty());
        assert_eq!((b.groups(), b.hosts()), (1, 0));
    }

    #[test]
    fn host_profile_takes_over_once_learned() {
        let mut b = Baselines::default();
        let group = "10.0.5.0/24";
        // Gruppe eingelernt mit kleinen Werten, der Server 10.0.5.2 macht immer viel Verkehr
        for _ in 0..40 {
            b.update(group, None, 10, &[5.0; FEATURES]);
        }
        for day in 0..5u16 {
            for _ in 0..5 {
                b.update(group, Some("10.0.5.2"), day * 24 + 10, &[15.0; FEATURES]);
            }
        }
        assert_eq!(b.reference(group, Some("10.0.5.2"), 10).map(|r| r.0), Some(SlotKind::Week), "Host hat erst 25 Stichproben");
        for _ in 0..5 {
            b.update(group, Some("10.0.5.2"), 10, &[15.0; FEATURES]);
        }
        let (kind, p) = b.reference(group, Some("10.0.5.2"), 34).unwrap();
        assert_eq!(kind, SlotKind::Host, "Dienstag teilt sich den Werktags-Slot");
        assert!((p[0].mean - 15.0).abs() < 1e-9);
        // Wochenende hat einen eigenen Host-Slot
        assert_ne!(b.reference(group, Some("10.0.5.2"), 5 * 24 + 10).map(|r| r.0), Some(SlotKind::Host));
        assert_eq!((b.groups(), b.hosts()), (1, 1));
    }
}
