// SPDX-License-Identifier: GPL-3.0-only
//
// Analysis engine. One O(D) pass scores every directory, a bounded heap keeps
// the top findings (O(D log K)), and reason strings are only built for the
// rows that survive. No filesystem access happens here.
//
// Score of a directory (0..=100):
//
//   share      = bytes on its filesystem pool / pool used space * 100
//   urgency    = 0.1 on a half-empty pool, rising to 1.0 at 90% full and 1.3 at
//                100%: a big directory on a healthy disk is not an incident
//   weight     = attention weight of its path class (/tmp 2.0, /home 1.5, ...)
//   expected   = 0.8 expected, 1.0 notable, 1.5 suspicious
//   age        = 1 + k * (fraction of its data that is stale), temp and home only
//   growth     = + up to 40 points, only when a baseline scan is supplied
//
//   score = min(100, share * urgency * weight * expected * age + growth)
//
// Severity thresholds default to 5 / 15 / 35 (medium / high / critical).
//
// Confidence: a directory's size is always a verified *lower bound* of what it
// really holds (unreadable subtrees count as zero). The score therefore never
// overstates, but with low coverage it can understate and rankings can miss
// the real culprit. Findings carry the confidence of their pool and are marked
// as lower bounds, and the overall verdict is "undetermined" rather than
// "healthy" when the scan is too incomplete to say.

use crate::coverage::{self, CoverageReport};
pub use crate::coverage::{Completeness, ScanConfidence};
use crate::fxhash::FxHashMap;
use crate::home::{self, HomeReport};
use crate::model::*;
use crate::nix::{self, DeadPaths, NixReport};
use crate::temp::{self, TempAssessment, TempReport};
use crate::topk::TopK;
use crate::users::UserNames;
pub use crate::zones::PathClass;
use crate::zones::HomeBucket;
use std::path::PathBuf;

const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }

    pub const ALL: [Severity; 4] = [Self::Low, Self::Medium, Self::High, Self::Critical];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expectation {
    /// Large is normal here (system files, the Nix store, toolchains).
    Expected,
    Notable,
    Suspicious,
}

impl Expectation {
    pub fn label(self) -> &'static str {
        match self {
            Self::Expected => "expected",
            Self::Notable => "notable",
            Self::Suspicious => "suspicious",
        }
    }

    fn factor(self) -> f64 {
        match self {
            Self::Expected => 0.8,
            Self::Notable => 1.0,
            Self::Suspicious => 1.5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingKind {
    Directory,
    Temporary,
    Home,
    Nix,
}

#[derive(Debug, Clone, Copy)]
pub struct Growth {
    pub previous_bytes: u64,
    pub delta_bytes: u64,
    pub percent: Option<f64>,
    pub elapsed_secs: i64,
    /// Points added to the score by this growth (0..=40).
    pub bonus: f64,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub node: NodeId,
    pub path: PathBuf,
    /// Set for findings that are about something other than the directory
    /// itself (stale temp data, reclaimable Nix garbage, build artifacts).
    pub title: Option<String>,
    pub kind: FindingKind,
    pub bytes: u64,
    pub percent_of_fs_used: f64,
    pub score: f64,
    pub severity: Severity,
    pub class: PathClass,
    pub expectation: Expectation,
    pub reasons: Vec<String>,
    pub error_count: u64,
    pub confidence: ScanConfidence,
    /// The real size may be larger than `bytes` (errors below, or low coverage).
    pub lower_bound: bool,
    pub fs: FsId,
    pub growth: Option<Growth>,
    pub stale_percent: f64,
}

#[derive(Debug, Clone)]
pub struct PoolScore {
    pub pool: usize,
    pub label: String,
    pub used_percent: f64,
    pub available_bytes: u64,
    pub urgency: f64,
    pub severity: Severity,
    pub coverage_percent: f64,
    pub confidence: ScanConfidence,
}

#[derive(Debug, Clone)]
pub struct RiskComponent {
    pub name: &'static str,
    /// 0.0 ..= 1.0
    pub value: f64,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct RiskScore {
    /// 0 ..= 100, noisy-OR of the components: independent problems add up but
    /// can never exceed 100.
    pub score: f64,
    pub level: Severity,
    pub components: Vec<RiskComponent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Qualifier {
    Confirmed,
    /// Real severity is at least this; the scan is incomplete.
    AtLeast,
    /// Too little was seen to call the system healthy.
    Undetermined,
}

#[derive(Debug, Clone, Copy)]
pub struct Overall {
    pub severity: Severity,
    pub qualifier: Qualifier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reliability {
    Reliable,
    Provisional,
    Unreliable,
}

#[derive(Debug, Clone)]
pub struct AnalysisConfig {
    pub max_findings: usize,
    pub min_finding_bytes: u64,
    pub medium_at: f64,
    pub high_at: f64,
    pub critical_at: f64,
    /// A directory is a pass-through container (and not reported itself) when
    /// one child holds at least this fraction of its bytes.
    pub dominant_child_ratio: f64,
    pub tmp_stale_days: u64,
    pub var_tmp_stale_days: u64,
    pub temp_large_bytes: u64,
    pub temp_stale_min_bytes: u64,
    pub artifact_report_bytes: u64,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            max_findings: 200,
            min_finding_bytes: MIB,
            medium_at: 5.0,
            high_at: 15.0,
            critical_at: 35.0,
            dominant_child_ratio: 0.9,
            tmp_stale_days: 7,
            var_tmp_stale_days: 30,
            temp_large_bytes: GIB,
            temp_stale_min_bytes: 64 * MIB,
            artifact_report_bytes: GIB,
        }
    }
}

impl AnalysisConfig {
    pub fn class_weight(&self, class: PathClass) -> f64 {
        match class {
            PathClass::Temporary => 2.0,
            PathClass::Home => 1.5,
            PathClass::Nix => 0.75,
            PathClass::Var => 1.25,
            PathClass::System => 0.5,
            PathClass::Generic => 1.0,
        }
    }

    pub fn severity(&self, score: f64) -> Severity {
        if score >= self.critical_at {
            Severity::Critical
        } else if score >= self.high_at {
            Severity::High
        } else if score >= self.medium_at {
            Severity::Medium
        } else {
            Severity::Low
        }
    }
}

/// Earlier scan to compare against, for growth scoring. Directories are keyed
/// by an incrementally computed path hash, so matching is O(1) per directory
/// and needs no path strings. Only directories at least `min_bytes` large are
/// kept, which bounds its size; a directory that is absent is treated as having
/// been smaller than that.
#[derive(Debug, Clone, Default)]
pub struct Baseline {
    pub taken_unix: i64,
    pub min_bytes: u64,
    sizes: FxHashMap<u64, u64>,
}

impl Baseline {
    pub fn from_scan(result: &ScanResult, min_bytes: u64) -> Self {
        let mut sizes = FxHashMap::default();
        for n in result.index.nodes() {
            if n.usage.bytes >= min_bytes {
                sizes.insert(n.path_hash, n.usage.bytes);
            }
        }
        Self {
            taken_unix: result.started_unix,
            min_bytes,
            sizes,
        }
    }

    pub fn len(&self) -> usize {
        self.sizes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sizes.is_empty()
    }
}

#[derive(Default)]
pub struct AnalysisInputs<'a> {
    pub baseline: Option<&'a Baseline>,
    /// Result of `nix::query_dead_paths`, when the caller asked for it.
    pub nix_dead: Option<&'a DeadPaths>,
    pub users: Option<UserNames>,
}

#[derive(Debug, Clone)]
pub struct AnalysisResult {
    pub coverage: CoverageReport,
    pub coverage_percent: f64,
    pub confidence: ScanConfidence,
    pub findings: Vec<Finding>,
    /// Directories that were scored as findings candidates (pass-through
    /// containers excluded), and how they split by severity.
    pub candidates: u64,
    pub severity_counts: [u64; 4],
    /// Indexed by `NodeId`: for a tree view that needs a severity per row.
    pub node_score: Vec<f32>,
    pub node_severity: Vec<Severity>,
    pub pool_scores: Vec<PoolScore>,
    pub risk: RiskScore,
    pub overall: Overall,
    pub temp: Vec<TempReport>,
    pub home: Vec<HomeReport>,
    pub nix: Option<NixReport>,
    pub has_baseline: bool,
}

impl AnalysisResult {
    pub fn ranked(&self) -> impl Iterator<Item = &Finding> {
        self.findings.iter()
    }

    pub fn highest_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    pub fn severity_count(&self, s: Severity) -> u64 {
        self.severity_counts[s as usize]
    }

    /// Whether "largest directory" style conclusions can be trusted.
    pub fn ranking_reliability(&self) -> (Reliability, Option<String>) {
        let c = &self.coverage;
        match c.completeness {
            Completeness::Complete => (Reliability::Reliable, None),
            Completeness::Substantial => (
                Reliability::Provisional,
                Some(format!(
                    "only {:.1}% of used space was seen; rankings are provisional",
                    c.coverage_percent
                )),
            ),
            Completeness::Partial => (
                Reliability::Provisional,
                Some(format!(
                    "only {:.1}% of used space was seen; the real largest directory may be in the unseen part",
                    c.coverage_percent
                )),
            ),
            Completeness::Minimal => (
                Reliability::Unreliable,
                Some(format!(
                    "only {:.1}% of used space was seen; these rankings do NOT show where the space went",
                    c.coverage_percent
                )),
            ),
        }
    }
}

// ---------------------------------------------------------------------------

fn urgency(p: f64) -> f64 {
    let p = p.clamp(0.0, 1.0);
    if p <= 0.5 {
        0.1
    } else if p <= 0.9 {
        0.1 + 0.9 * (p - 0.5) / 0.4
    } else {
        1.0 + 0.3 * ((p - 0.9) / 0.1).min(1.0)
    }
}

fn pool_severity(p: f64) -> Severity {
    if p >= 0.95 {
        Severity::Critical
    } else if p >= 0.90 {
        Severity::High
    } else if p >= 0.80 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

fn sat(x: f64) -> f64 {
    x.clamp(0.0, 1.0)
}

struct Scored {
    score: f64,
    share_pct: f64,
    expectation: Expectation,
    growth: Option<Growth>,
    stale_fraction: f64,
}

struct Engine<'a> {
    result: &'a ScanResult,
    cfg: &'a AnalysisConfig,
    baseline: Option<&'a Baseline>,
    pool_used: Vec<u64>,
    pool_urgency: Vec<f64>,
    pool_conf: Vec<ScanConfidence>,
    pool_pressure: Vec<f64>,
    temp_bucket: usize,
    home_bucket: usize,
}

impl<'a> Engine<'a> {
    fn pool_of(&self, n: &DirNode) -> usize {
        self.result.filesystems[n.fs as usize].pool
    }

    fn score_bytes(
        &self,
        n: &DirNode,
        bytes: u64,
        stale_fraction: f64,
        expectation: Expectation,
        growth: Option<Growth>,
    ) -> Scored {
        let pool = self.pool_of(n);
        let share_pct = bytes as f64 / self.pool_used[pool].max(1) as f64 * 100.0;
        let age_factor = match n.class {
            PathClass::Temporary => 1.0 + 0.5 * stale_fraction,
            PathClass::Home => 1.0 + 0.25 * stale_fraction,
            _ => 1.0,
        };
        let bonus = growth.map_or(0.0, |g| g.bonus);
        let score = (share_pct
            * self.pool_urgency[pool]
            * self.cfg.class_weight(n.class)
            * expectation.factor()
            * age_factor
            + bonus)
            .min(100.0);
        Scored {
            score,
            share_pct,
            expectation,
            growth,
            stale_fraction,
        }
    }

    fn growth_for(&self, n: &DirNode) -> Option<Growth> {
        let base = self.baseline?;
        let prev = base.sizes.get(&n.path_hash).copied().unwrap_or(0);
        let now = n.usage.bytes;
        if now <= prev || now - prev < MIB {
            return None;
        }
        let delta = now - prev;
        let elapsed = (self.result.started_unix - base.taken_unix).max(3600);
        let pool = self.pool_of(n);
        let abs_pct = delta as f64 / self.pool_used[pool].max(1) as f64 * 100.0;
        let rate_pct_per_day = abs_pct / (elapsed as f64 / 86_400.0);
        let rel = delta as f64 / prev.max(MIB) as f64;
        Some(Growth {
            previous_bytes: prev,
            delta_bytes: delta,
            percent: (prev > 0).then(|| delta as f64 / prev as f64 * 100.0),
            elapsed_secs: elapsed,
            bonus: 40.0 * sat(rate_pct_per_day / 5.0) * sat(rel / 2.0),
        })
    }

    fn stale_fraction(&self, n: &DirNode) -> f64 {
        let bucket = match n.class {
            PathClass::Temporary => self.temp_bucket,
            PathClass::Home => self.home_bucket,
            _ => return 0.0,
        };
        if n.usage.bytes == 0 {
            0.0
        } else {
            n.usage.bytes_older_than(bucket) as f64 / n.usage.bytes as f64
        }
    }

    fn expectation(&self, n: &DirNode, stale: f64, growth: &Option<Growth>) -> Expectation {
        let bytes = n.usage.bytes;
        if let Some(g) = growth {
            if g.percent.is_none_or(|p| p >= 100.0) && g.bonus >= 10.0 {
                return Expectation::Suspicious;
            }
        }
        match n.class {
            PathClass::System | PathClass::Nix => Expectation::Expected,
            PathClass::Temporary => {
                if stale >= 0.5 && bytes >= self.cfg.temp_stale_min_bytes {
                    Expectation::Suspicious
                } else if bytes >= self.cfg.temp_large_bytes {
                    Expectation::Notable
                } else {
                    Expectation::Expected
                }
            }
            PathClass::Home => {
                if n.flags & flags::PROJECT != 0 {
                    return Expectation::Expected;
                }
                match n.home_bucket() {
                    Some(HomeBucket::Cache | HomeBucket::Downloads) => {
                        if stale >= 0.7 && bytes >= GIB {
                            Expectation::Suspicious
                        } else {
                            Expectation::Notable
                        }
                    }
                    Some(
                        HomeBucket::Cargo
                        | HomeBucket::Toolchains
                        | HomeBucket::Local
                        | HomeBucket::Config,
                    ) => Expectation::Expected,
                    _ => Expectation::Notable,
                }
            }
            PathClass::Var | PathClass::Generic => Expectation::Notable,
        }
    }

    fn score_node(&self, n: &DirNode) -> Scored {
        let growth = self.growth_for(n);
        let stale = self.stale_fraction(n);
        let exp = self.expectation(n, stale, &growth);
        self.score_bytes(n, n.usage.fs_bytes, stale, exp, growth)
    }

    fn confidence_of(&self, n: &DirNode) -> ScanConfidence {
        let c = self.pool_conf[self.pool_of(n)];
        if n.usage.counts.errors > 0 { c.downgrade() } else { c }
    }

    fn reasons(&self, id: NodeId, n: &DirNode, s: &Scored, severity: Severity) -> Vec<String> {
        let mut r = Vec::new();
        if s.share_pct >= 10.0 {
            r.push("large share of filesystem used space".to_string());
        } else if s.share_pct >= 5.0 {
            r.push("meaningful share of filesystem used space".to_string());
        }
        if n.class != PathClass::Generic {
            r.push(format!("{} attention zone", n.class.label()));
        }
        let pool = self.pool_of(n);
        if self.pool_pressure[pool] >= 0.9 {
            r.push(format!(
                "filesystem is {:.0}% full, which raises urgency",
                self.pool_pressure[pool] * 100.0
            ));
        }
        if severity >= Severity::High {
            r.push(format!("weighted storage pressure is {}", severity.label().to_lowercase()));
        }
        match s.expectation {
            Expectation::Suspicious => r.push("classified suspicious".to_string()),
            Expectation::Expected if n.class == PathClass::System || n.class == PathClass::Nix => {
                r.push("expected to be large (system/nix data)".to_string())
            }
            _ => {}
        }
        if s.stale_fraction >= 0.3 {
            let days = if n.class == PathClass::Temporary {
                self.cfg.tmp_stale_days
            } else {
                90
            };
            r.push(format!(
                "{:.0}% of the data has not been modified for {days}+ days",
                s.stale_fraction * 100.0
            ));
        }
        if let Some(g) = &s.growth {
            r.push(format!(
                "grew by {}{} since the baseline scan {} ago",
                fmt_bytes(g.delta_bytes),
                g.percent.map_or(String::new(), |p| format!(" (+{p:.0}%)")),
                fmt_duration(g.elapsed_secs)
            ));
        }
        if let Some(b) = n.home_bucket() {
            r.push(format!("home bucket: {}", b.label()));
        }
        if n.flags & flags::PROJECT != 0 {
            r.push("project directory".to_string());
        }
        if n.flags & flags::DENIED != 0 {
            r.push("directory unreadable (permission denied): contents not counted".to_string());
        }
        if n.usage.counts.errors > 0 {
            r.push(format!("{} inaccessible/error entries below path", n.usage.counts.errors));
        }
        let conf = self.confidence_of(n);
        if conf != ScanConfidence::High {
            r.push(format!(
                "scan confidence {}: size is a lower bound",
                conf.label()
            ));
        }
        let _ = id;
        r
    }

    fn build_finding(&self, id: NodeId, s: &Scored) -> Finding {
        let n = self.result.index.node(id);
        let severity = self.cfg.severity(s.score);
        let conf = self.confidence_of(n);
        Finding {
            node: id,
            path: self.result.index.path(id),
            title: None,
            kind: match n.class {
                PathClass::Temporary => FindingKind::Temporary,
                PathClass::Home => FindingKind::Home,
                PathClass::Nix => FindingKind::Nix,
                _ => FindingKind::Directory,
            },
            bytes: n.usage.fs_bytes,
            percent_of_fs_used: s.share_pct,
            score: s.score,
            severity,
            class: n.class,
            expectation: s.expectation,
            reasons: self.reasons(id, n, s, severity),
            error_count: n.usage.counts.errors,
            confidence: conf,
            lower_bound: conf != ScanConfidence::High || n.usage.counts.errors > 0,
            fs: n.fs,
            growth: s.growth,
            stale_percent: s.stale_fraction * 100.0,
        }
    }

    /// A finding about `bytes` of something inside/at `node` that is not the
    /// directory's own total (reclaimable garbage, stale temp data, ...).
    fn synthetic(
        &self,
        node: NodeId,
        bytes: u64,
        title: String,
        kind: FindingKind,
        expectation: Expectation,
        mut reasons: Vec<String>,
    ) -> Finding {
        let n = self.result.index.node(node);
        let s = self.score_bytes(n, bytes, 0.0, expectation, None);
        let severity = self.cfg.severity(s.score);
        let conf = self.confidence_of(n);
        reasons.push(format!(
            "{:.1}% of filesystem used space",
            s.share_pct
        ));
        if conf != ScanConfidence::High {
            reasons.push(format!("scan confidence {}", conf.label()));
        }
        Finding {
            node,
            path: self.result.index.path(node),
            title: Some(title),
            kind,
            bytes,
            percent_of_fs_used: s.share_pct,
            score: s.score,
            severity,
            class: n.class,
            expectation,
            reasons,
            error_count: n.usage.counts.errors,
            confidence: conf,
            lower_bound: conf != ScanConfidence::High,
            fs: n.fs,
            growth: None,
            stale_percent: 0.0,
        }
    }
}

pub fn fmt_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 { format!("{bytes} B") } else { format!("{v:.2} {}", UNITS[u]) }
}

fn fmt_duration(secs: i64) -> String {
    if secs >= 2 * 86_400 {
        format!("{} days", secs / 86_400)
    } else if secs >= 7200 {
        format!("{} hours", secs / 3600)
    } else {
        format!("{} minutes", (secs / 60).max(1))
    }
}

pub fn analyze(result: &ScanResult, config: &AnalysisConfig) -> AnalysisResult {
    analyze_with(result, config, &AnalysisInputs::default())
}

pub fn analyze_with(
    result: &ScanResult,
    cfg: &AnalysisConfig,
    inputs: &AnalysisInputs,
) -> AnalysisResult {
    let cov = coverage::assess(result);
    let users = inputs.users.clone().unwrap_or_else(UserNames::load);

    let np = result.pools.len();
    let mut pool_used = vec![0u64; np];
    let mut pool_urgency = vec![0.1; np];
    let mut pool_pressure = vec![0.0; np];
    let mut pool_conf = vec![ScanConfidence::Low; np];
    for (i, p) in result.pools.iter().enumerate() {
        pool_used[i] = p.info.used_bytes;
        let pr = if p.info.total_bytes == 0 {
            0.0
        } else {
            p.info.used_bytes as f64 / p.info.total_bytes as f64
        };
        pool_pressure[i] = pr;
        pool_urgency[i] = urgency(pr);
    }
    for pc in &cov.pools {
        pool_conf[pc.pool] = pc.confidence;
    }

    let eng = Engine {
        result,
        cfg,
        baseline: inputs.baseline,
        pool_used,
        pool_urgency,
        pool_conf,
        pool_pressure,
        temp_bucket: bucket_from_days(cfg.tmp_stale_days),
        home_bucket: bucket_from_days(90),
    };

    // ---- O(D): dominant-child pass (children always have larger ids) ----
    let nodes = result.index.nodes();
    let n = nodes.len();
    let mut max_child = vec![0u64; n];
    for i in 1..n {
        let p = nodes[i].parent.idx();
        let b = nodes[i].usage.bytes;
        if b > max_child[p] {
            max_child[p] = b;
        }
    }

    // ---- O(D): score everything, keep top-K by heap ----
    let mut node_score = vec![0f32; n];
    let mut node_severity = vec![Severity::Low; n];
    let mut counts = [0u64; 4];
    let mut candidates = 0u64;
    let mut heap: TopK<(NodeId, f64)> = TopK::new(cfg.max_findings);
    let mut zone_roots: Vec<NodeId> = result.zones.iter().map(|z| z.node).collect();
    zone_roots.sort_unstable();

    for (i, node) in nodes.iter().enumerate() {
        if i == 0 || node.flags & (flags::EXCLUDED | flags::SKIPPED_MOUNT) != 0 {
            continue;
        }
        if node.usage.fs_bytes < cfg.min_finding_bytes {
            continue;
        }
        let s = eng.score_node(node);
        let sev = cfg.severity(s.score);
        node_score[i] = s.score as f32;
        node_severity[i] = sev;

        let container = node.usage.bytes > 0
            && max_child[i] as f64 >= cfg.dominant_child_ratio * node.usage.bytes as f64;
        if container {
            continue;
        }
        candidates += 1;
        counts[sev as usize] += 1;
        let key = ((s.score * 1e6) as u64, node.usage.bytes);
        if heap.might_accept(key.0) {
            heap.push(key, (NodeId(i as u32), s.score));
        }
    }

    let mut findings: Vec<Finding> = heap
        .into_sorted_desc()
        .into_iter()
        .map(|(id, _)| {
            let s = eng.score_node(result.index.node(id));
            eng.build_finding(id, &s)
        })
        .collect();

    // ---- specialised reports, and the findings they add or sharpen ----
    let temp_reports = temp::build(result, cfg, &users);
    let home_reports = home::build(result, cfg, &users);
    let nix_report = nix::build(result, inputs.nix_dead);

    for t in &temp_reports {
        let mut extra = Vec::new();
        if t.ram_backed {
            extra.push(format!("{} is RAM-backed ({}): contents consume memory", t.label, t.fstype));
        }
        if let Some(top) = t.owners.first() {
            if top.percent >= 60.0 {
                extra.push(format!("{:.0}% of the data is owned by {}", top.percent, top.name));
            }
        }
        if matches!(t.assessment, TempAssessment::Stale | TempAssessment::LargeAndStale) {
            extra.push(format!(
                "{} ({:.0}%) untouched for {}+ days",
                fmt_bytes(t.stale_bytes),
                t.stale_percent,
                t.stale_after_days
            ));
            let title = format!("stale temporary data in {}", t.label);
            findings.push(eng.synthetic(
                t.node,
                t.stale_bytes,
                title,
                FindingKind::Temporary,
                Expectation::Suspicious,
                extra.clone(),
            ));
        } else if t.assessment == TempAssessment::Large {
            findings.push(eng.synthetic(
                t.node,
                t.bytes,
                format!("unusually large temporary tree {}", t.label),
                FindingKind::Temporary,
                Expectation::Notable,
                extra.clone(),
            ));
        }
        if let Some(f) = findings.iter_mut().find(|f| f.node == t.node && f.title.is_none()) {
            f.reasons.extend(extra);
        }
    }

    for h in &home_reports {
        if h.artifact_total_bytes >= cfg.artifact_report_bytes {
            let names: Vec<String> = h
                .projects
                .iter()
                .flat_map(|p| p.artifacts.iter().map(|a| a.0.clone()))
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            findings.push(eng.synthetic(
                h.node,
                h.artifact_total_bytes,
                format!("regenerable build artifacts in projects under {}", h.label),
                FindingKind::Home,
                Expectation::Notable,
                vec![format!("directories: {}", names.join(", "))],
            ));
        }
    }

    if let Some(nr) = &nix_report {
        if let (Some(node), Some(rec)) = (nr.store_node, nix::reclaimable_bytes(nr)) {
            if rec >= GIB {
                findings.push(eng.synthetic(
                    node,
                    rec,
                    "garbage-collectable Nix store data".to_string(),
                    FindingKind::Nix,
                    Expectation::Notable,
                    vec!["unreferenced store paths per the Nix tools".to_string()],
                ));
            }
        }
        if let (Some(node), Some(sys)) = (
            nr.store_node,
            nr.generations.iter().find(|g| g.profile == "system" && g.count >= 20),
        ) {
            findings.push(eng.synthetic(
                node,
                nr.store_bytes,
                format!("{} NixOS system generations retain old closures", sys.count),
                FindingKind::Nix,
                Expectation::Notable,
                vec!["old generations keep their closures out of garbage collection".to_string()],
            ));
        }
    }

    findings.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| b.bytes.cmp(&a.bytes))
            .then_with(|| a.path.cmp(&b.path))
    });
    findings.truncate(cfg.max_findings);

    // ---- per-pool scores ----
    let pool_scores: Vec<PoolScore> = cov
        .pools
        .iter()
        .map(|p| {
            let pr = if p.total_bytes == 0 {
                0.0
            } else {
                p.used_bytes as f64 / p.total_bytes as f64
            };
            PoolScore {
                pool: p.pool,
                label: p.label.clone(),
                used_percent: pr * 100.0,
                available_bytes: p.available_bytes,
                urgency: urgency(pr),
                severity: pool_severity(pr),
                coverage_percent: p.coverage_percent,
                confidence: p.confidence,
            }
        })
        .collect();

    // ---- combined SOC-style risk ----
    let capacity = pool_scores
        .iter()
        .map(|p| sat((p.used_percent / 100.0 - 0.7) / 0.27))
        .fold(0.0, f64::max);
    let worst_pool = pool_scores.iter().max_by(|a, b| a.used_percent.total_cmp(&b.used_percent));
    let top_non_temp = findings
        .iter()
        .filter(|f| f.kind != FindingKind::Temporary)
        .map(|f| f.score)
        .fold(0.0, f64::max);
    let top_temp = findings
        .iter()
        .filter(|f| f.kind == FindingKind::Temporary)
        .map(|f| f.score)
        .fold(0.0, f64::max);
    let growth = findings
        .iter()
        .filter_map(|f| f.growth.map(|g| g.bonus))
        .fold(0.0, f64::max);
    let blind = if cov.subtree {
        0.0
    } else {
        (1.0 - cov.coverage_percent / 100.0) * capacity
    };
    let components = vec![
        RiskComponent {
            name: "capacity",
            value: capacity,
            detail: worst_pool.map_or("no filesystem".into(), |p| {
                format!("{} is {:.1}% full", p.label, p.used_percent)
            }),
        },
        RiskComponent {
            name: "concentration",
            value: sat(top_non_temp / 100.0),
            detail: format!("highest directory score {top_non_temp:.1}"),
        },
        RiskComponent {
            name: "temporary data",
            value: sat(top_temp / 100.0),
            detail: format!("highest temporary-data score {top_temp:.1}"),
        },
        RiskComponent {
            name: "growth",
            value: sat(growth / 40.0),
            detail: if inputs.baseline.is_some() {
                format!("largest growth bonus {growth:.1}/40")
            } else {
                "no baseline scan supplied".into()
            },
        },
        RiskComponent {
            name: "blind spot",
            value: blind,
            detail: format!(
                "{:.1}% of used space unseen on a {:.0}%-pressure system",
                100.0 - cov.coverage_percent,
                capacity * 100.0
            ),
        },
    ];
    let risk_score = 100.0 * (1.0 - components.iter().map(|c| 1.0 - c.value).product::<f64>());
    let risk = RiskScore {
        score: risk_score,
        level: if risk_score >= 60.0 {
            Severity::Critical
        } else if risk_score >= 30.0 {
            Severity::High
        } else if risk_score >= 10.0 {
            Severity::Medium
        } else {
            Severity::Low
        },
        components,
    };

    // ---- overall verdict, honest about incomplete scans ----
    let worst = findings
        .iter()
        .map(|f| f.severity)
        .chain(pool_scores.iter().map(|p| p.severity))
        .max()
        .unwrap_or(Severity::Low);
    let qualifier = if cov.confidence == ScanConfidence::High {
        Qualifier::Confirmed
    } else if worst >= Severity::High {
        Qualifier::AtLeast
    } else {
        Qualifier::Undetermined
    };

    let mut node_sev_hist = counts;
    // Keep counters monotone with retained findings (synthetic ones included).
    for f in findings.iter().filter(|f| f.title.is_some()) {
        node_sev_hist[f.severity as usize] += 1;
    }

    AnalysisResult {
        coverage_percent: cov.coverage_percent,
        confidence: cov.confidence,
        coverage: cov,
        findings,
        candidates,
        severity_counts: node_sev_hist,
        node_score,
        node_severity,
        pool_scores,
        risk,
        overall: Overall { severity: worst, qualifier },
        temp: temp_reports,
        home: home_reports,
        nix: nix_report,
        has_baseline: inputs.baseline.is_some(),
    }
}
