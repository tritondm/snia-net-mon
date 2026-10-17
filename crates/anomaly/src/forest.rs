//! Isolation Forest (Variante 2, „zweite Meinung“) nach Liu, Ting & Zhou (2008).
//!
//! Jeder Baum teilt eine Zufallsstichprobe der Trainingsvektoren an zufälligen Stellen zufällig gewählter Merkmale auf,
//! bis jeder Punkt allein steht oder die Höhengrenze erreicht ist. Ausreißer sind nach wenigen Teilungen isoliert, normale
//! Punkte erst nach vielen. Der Score `2^(-E[h(x)] / c(ψ))` liegt zwischen 0 und 1; um 0,5 ist unauffällig, nahe 1 sehr
//! auffällig.
//!
//! Merkmalsvektor: die sieben logarithmierten Merkmale aus [`crate::features`], Upload-Anteil, Tageszeit als Sinus und
//! Kosinus, Wochenende. So fallen auch Kombinationen auf, bei denen jeder Einzelwert normal ist (z. B. nachts viele
//! Länder über ungewöhnliche Ports).

use crate::features::{FEATURES, HostWindow};

pub const DIMS: usize = FEATURES + 4;
pub const SHARE: usize = FEATURES;
/// Erste Dimension der Zeitmerkmale (Sinus, Kosinus, Wochenende) – gehen nicht in die Erklärung ein.
pub const TIME: usize = FEATURES + 1;
pub type Vector = [f64; DIMS];

pub const TREES: usize = 100;
pub const SAMPLE: usize = 256;

/// Merkmalsvektor eines Hosts. `log` sind die logarithmierten Merkmale, `hour` die Ortszeit in Stunden (mit Bruchteil).
pub fn vector(log: &[f64; FEATURES], host: &HostWindow, hour: f64, weekend: bool) -> Vector {
    let mut v = [0.0; DIMS];
    v[..FEATURES].copy_from_slice(log);
    v[SHARE] = host.upload_share();
    let angle = hour / 24.0 * std::f64::consts::TAU;
    v[TIME] = angle.sin();
    v[TIME + 1] = angle.cos();
    v[TIME + 2] = if weekend { 1.0 } else { 0.0 };
    v
}

/// Kleiner, reproduzierbarer Zufallsgenerator (SplitMix64) – mehr braucht der Wald nicht.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n.max(1) as u64) as usize
    }

    /// Gleichverteilt in [0, 1).
    pub fn unit(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 / (1u64 << 53) as f64
    }
}

enum Node {
    Leaf { size: usize },
    Split { dim: usize, value: f64, left: usize, right: usize },
}

struct Tree {
    nodes: Vec<Node>,
}

impl Tree {
    fn build(data: &[Vector], idx: &mut [usize], limit: usize, rng: &mut Rng) -> Self {
        let mut tree = Tree { nodes: Vec::new() };
        tree.grow(data, idx, 0, limit, rng);
        tree
    }

    fn grow(&mut self, data: &[Vector], idx: &mut [usize], depth: usize, limit: usize, rng: &mut Rng) -> usize {
        let id = self.nodes.len();
        self.nodes.push(Node::Leaf { size: idx.len() });
        if idx.len() <= 1 || depth >= limit {
            return id;
        }
        // Nur Merkmale, die in diesem Knoten noch streuen
        let ranges: Vec<(usize, f64, f64)> = (0..DIMS)
            .filter_map(|dim| {
                let (lo, hi) = idx.iter().fold((f64::INFINITY, f64::NEG_INFINITY), |(lo, hi), &i| (lo.min(data[i][dim]), hi.max(data[i][dim])));
                (hi > lo).then_some((dim, lo, hi))
            })
            .collect();
        if ranges.is_empty() {
            return id;
        }
        let (dim, lo, hi) = ranges[rng.below(ranges.len())];
        let value = lo + rng.unit() * (hi - lo);
        let mut split = 0;
        for k in 0..idx.len() {
            if data[idx[k]][dim] < value {
                idx.swap(k, split);
                split += 1;
            }
        }
        let (left_idx, right_idx) = idx.split_at_mut(split);
        let left = self.grow(data, left_idx, depth + 1, limit, rng);
        let right = self.grow(data, right_idx, depth + 1, limit, rng);
        self.nodes[id] = Node::Split { dim, value, left, right };
        id
    }

    fn path_length(&self, x: &Vector) -> f64 {
        let mut node = 0;
        let mut depth = 0.0;
        loop {
            match self.nodes[node] {
                Node::Leaf { size } => return depth + c(size as f64),
                Node::Split { dim, value, left, right } => {
                    node = if x[dim] < value { left } else { right };
                    depth += 1.0;
                }
            }
        }
    }
}

/// Mittlere Pfadlänge einer erfolglosen Suche im binären Suchbaum mit `n` Elementen (Normierung des Scores).
fn c(n: f64) -> f64 {
    if n > 2.0 {
        2.0 * ((n - 1.0).ln() + 0.577_215_664_9) - 2.0 * (n - 1.0) / n
    } else if n == 2.0 {
        1.0
    } else {
        0.0
    }
}

pub struct Forest {
    trees: Vec<Tree>,
    norm: f64,
}

impl Forest {
    /// Wald trainieren; `None` bei zu wenigen Daten.
    pub fn train(data: &[Vector], trees: usize, sample: usize, rng: &mut Rng) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }
        let sample = sample.min(data.len());
        let limit = (sample as f64).log2().ceil() as usize;
        let trees = (0..trees)
            .map(|_| {
                let mut idx: Vec<usize> = (0..sample).map(|_| rng.below(data.len())).collect();
                Tree::build(data, &mut idx, limit, rng)
            })
            .collect();
        Some(Self { trees, norm: c(sample as f64) })
    }

    pub fn score(&self, x: &Vector) -> f64 {
        let mean = self.trees.iter().map(|t| t.path_length(x)).sum::<f64>() / self.trees.len() as f64;
        2f64.powf(-mean / self.norm)
    }
}

/// Verteilung der Scores auf den Trainingsdaten – Grundlage der wirksamen Schwelle und Hilfe beim Einstellen.
#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
pub struct Quantiles {
    pub p50: f64,
    pub p99: f64,
    pub p999: f64,
    pub max: f64,
}

/// Score-Quantile über höchstens 20 000 Trainingsvektoren (gleichmäßig ausgedünnt).
pub fn score_quantiles(forest: &Forest, data: &[Vector]) -> Quantiles {
    let step = data.len().div_ceil(20_000).max(1);
    let mut scores: Vec<f64> = data.iter().step_by(step).map(|v| forest.score(v)).collect();
    if scores.is_empty() {
        return Quantiles::default();
    }
    scores.sort_by(f64::total_cmp);
    let q = |p: f64| scores[((scores.len() - 1) as f64 * p).round() as usize];
    Quantiles { p50: q(0.5), p99: q(0.99), p999: q(0.999), max: q(1.0) }
}

/// Median und MAD je Dimension der Trainingsdaten – damit lässt sich zu einem ML-Treffer zeigen, welche Merkmale am
/// stärksten vom Typischen abweichen.
pub fn median_mad(data: &[Vector]) -> (Vector, Vector) {
    let mut median = [0.0; DIMS];
    let mut mad = [0.0; DIMS];
    if data.is_empty() {
        return (median, mad);
    }
    let mut column = vec![0.0; data.len()];
    for dim in 0..DIMS {
        column.iter_mut().zip(data).for_each(|(c, v)| *c = v[dim]);
        column.sort_by(f64::total_cmp);
        median[dim] = column[column.len() / 2];
        column.iter_mut().for_each(|c| *c = (*c - median[dim]).abs());
        column.sort_by(f64::total_cmp);
        mad[dim] = column[column.len() / 2];
    }
    (median, mad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outliers_score_higher_than_normal_points() {
        let mut rng = Rng::new(7);
        // Normaler Verkehr: alle Merkmale glockenförmig um 5,5 (Summe von vier Gleichverteilungen)
        let data: Vec<Vector> = (0..2000).map(|_| std::array::from_fn(|_| 3.5 + (0..4).map(|_| rng.unit()).sum::<f64>())).collect();
        let forest = Forest::train(&data, TREES, SAMPLE, &mut rng).unwrap();
        let normal = forest.score(&[5.5; DIMS]);
        // Ausreißer in mehreren Merkmalen gleichzeitig (Volumen, Ziele, Ports, Länder …)
        let mut odd = [5.5; DIMS];
        odd[..7].fill(12.0);
        let odd_score = forest.score(&odd);
        let quantiles = score_quantiles(&forest, &data);
        assert!(normal < quantiles.p50, "normaler Punkt: {normal} / Median {}", quantiles.p50);
        assert!(odd_score > quantiles.max && odd_score > 0.65, "Ausreißer: {odd_score} / Training max {}", quantiles.max);

        let (median, mad) = median_mad(&data);
        assert!((median[0] - 5.5).abs() < 0.05);
        assert!(mad[0] > 0.2 && mad[0] < 0.5, "MAD {}", mad[0]);
    }

    #[test]
    fn too_little_data_gives_no_model() {
        assert!(Forest::train(&[[0.0; DIMS]], TREES, SAMPLE, &mut Rng::new(1)).is_none());
        // lauter gleiche Punkte: kein Merkmal streut, Bäume bleiben Blätter, trotzdem ein gültiger Score
        let forest = Forest::train(&[[1.0; DIMS]; 10], 10, SAMPLE, &mut Rng::new(1)).unwrap();
        assert!(forest.score(&[1.0; DIMS]).is_finite());
    }
}
