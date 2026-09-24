use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering::Relaxed},
        Arc, RwLock,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Semaphore,
    time::timeout,
};

const LISTEN_HOST: &str = "127.0.0.1";
const UPSTREAM_HOST: &str = "127.0.0.1";
const PRODUCTION_PORT_PAIRS: &[(u16, u16)] = &[(5335, 5336), (5337, 5338)];
const TEST_PORT_PAIRS: &[(u16, u16)] = &[(15335, 5336), (15337, 5338)];
const PRODUCTION_METRICS_PORT: u16 = 5339;
const TEST_METRICS_PORT: u16 = 15339;
const UDP_LIMIT: usize = 65_535;
/// Queries allowed to wait on Unbound at once, shared by both port pairs.
/// Beyond this the proxy drops new queries instead of growing without bound
/// during a flood; clients retry. Overridable with EVADE_MAX_INFLIGHT_UDP/TCP.
const DEFAULT_MAX_INFLIGHT_UDP: usize = 4096;
const DEFAULT_MAX_INFLIGHT_TCP: usize = 1024;
/// How long an idle client TCP connection is kept open for further queries
/// (RFC 7766 pipelining) before the proxy closes it.
const TCP_IDLE: Duration = Duration::from_secs(10);
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Default, PartialEq)]
struct TestRedirect {
    v4: Option<u32>,
    v6: Option<u128>,
    expires_at: Option<f64>,
}

struct RuntimeConfig {
    test_mode: bool,
    redirects: HashMap<String, TestRedirect>,
}

impl RuntimeConfig {
    fn parse() -> Result<Self> {
        let mut test_mode = false;
        let mut redirects: HashMap<String, TestRedirect> = HashMap::new();
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--test" => test_mode = true,
                "--redirect" => {
                    let rule = args.next().context("--redirect requires DOMAIN=IP")?;
                    add_redirect(&mut redirects, &rule)?;
                }
                "--help" | "-h" => {
                    println!(
                        "evade-proxy\n\n  --test                 listen on 15335/15337; metrics on 15339\n  --redirect DOMAIN=IP   override A or AAAA answers in test mode (repeatable)\n  -h, --help             show this help"
                    );
                    std::process::exit(0);
                }
                _ if arg.starts_with("--redirect=") => {
                    add_redirect(&mut redirects, &arg[11..])?;
                }
                _ => bail!("unknown argument {arg:?}; use --help"),
            }
        }
        if !test_mode && !redirects.is_empty() {
            bail!("--redirect is only accepted together with --test");
        }
        Ok(Self {
            test_mode,
            redirects,
        })
    }

    fn port_pairs(&self) -> &'static [(u16, u16)] {
        if self.test_mode {
            TEST_PORT_PAIRS
        } else {
            PRODUCTION_PORT_PAIRS
        }
    }

    fn metrics_port(&self) -> u16 {
        if self.test_mode {
            TEST_METRICS_PORT
        } else {
            PRODUCTION_METRICS_PORT
        }
    }
}

fn add_redirect(rules: &mut HashMap<String, TestRedirect>, rule: &str) -> Result<()> {
    let (domain, ip) = rule
        .split_once('=')
        .with_context(|| format!("invalid redirect {rule:?}; expected DOMAIN=IP"))?;
    let domain = normalize_domain(domain)?;
    let target = rules.entry(domain).or_default();
    if let Ok(ip) = ip.parse::<Ipv4Addr>() {
        target.v4 = Some(u32::from(ip));
    } else if let Ok(ip) = ip.parse::<Ipv6Addr>() {
        target.v6 = Some(u128::from(ip));
    } else {
        bail!("invalid redirect address {ip:?}");
    }
    Ok(())
}

fn normalize_domain(domain: &str) -> Result<String> {
    let normalized = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.len() > 253
        || normalized
            .split('.')
            .any(|label| label.is_empty() || label.len() > 63)
    {
        bail!("invalid domain {domain:?}");
    }
    Ok(normalized)
}

/// TTL por defecto de las respuestas reescritas. Las listas se recargan cada
/// 5 s, así que 30 s acota el tiempo que un cliente puede seguir usando una IP
/// sustituta que haya pasado a estar bloqueada, y evita que cada conexión a un
/// dominio evadido vuelva a consultar al servidor (antes TTL=0).
const DEFAULT_REWRITE_TTL: u32 = 30;
// Cap client caching before an address becomes blocked, without changing the
// upstream Unbound cache. Applies to Cloudflare addresses and SVCB/HTTPS hints.
const CLOUDFLARE_MAX_TTL: u32 = 30;

#[derive(Clone, Debug)]
struct Paths {
    blocked_v4: PathBuf,
    blocked_v6: PathBuf,
    cf_v4: PathBuf,
    cf_v6: PathBuf,
    stats: PathBuf,
    redirects: PathBuf,
    /// TTL (segundos) que se escribe en los RR de una respuesta reescrita.
    /// 0 reproduce el comportamiento antiguo (sin caché en el cliente).
    rewrite_ttl: u32,
}

impl Paths {
    fn from_env(test_mode: bool) -> Self {
        fn value(name: &str, default: &str) -> PathBuf {
            std::env::var_os(name)
                .map(PathBuf::from)
                .unwrap_or_else(|| default.into())
        }
        Self {
            blocked_v4: value("EVADE_BLOCKED_IPV4_FILE", "/etc/unbound/blocked_ips.txt"),
            blocked_v6: value("EVADE_BLOCKED_IPV6_FILE", "/etc/unbound/blocked_ipv6.txt"),
            cf_v4: value(
                "EVADE_CF_IPV4_FILE",
                "/etc/unbound/cloudflare_official_v4.txt",
            ),
            cf_v6: value(
                "EVADE_CF_IPV6_FILE",
                "/etc/unbound/cloudflare_official_v6.txt",
            ),
            stats: value(
                "EVADE_STATS_FILE",
                if test_mode {
                    "/tmp/evade-proxy-test-stats.json"
                } else {
                    "/root/xpd-dns/scripts/evade_stats.json"
                },
            ),
            redirects: value("EVADE_REDIRECTS_FILE", "/run/evade-proxy/redirects.txt"),
            rewrite_ttl: std::env::var("EVADE_REWRITE_TTL")
                .ok()
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(DEFAULT_REWRITE_TTL),
        }
    }
}

#[derive(Clone, Default)]
struct Data {
    blocked_v4: HashSet<u32>,
    blocked_v6: HashSet<u128>,
    cf_v4: Vec<(u32, u32)>,
    cf_v6: Vec<(u128, u128)>,
    // Precomputed at reload time (blocked IP -> free neighbor), so the per-packet
    // rewrite path is a HashMap lookup instead of re-scanning the prefix every time
    // the same blocked anycast IP shows up in yet another answer.
    evasion_v4: HashMap<u32, u32>,
    evasion_v6: HashMap<u128, u128>,
}

impl Data {
    fn new(
        blocked_v4: HashSet<u32>,
        blocked_v6: HashSet<u128>,
        cf_v4: Vec<(u32, u32)>,
        cf_v6: Vec<(u128, u128)>,
    ) -> Self {
        let evasion_v4 = blocked_v4
            .iter()
            .filter_map(|&ip| scan_evasive_v4(ip, &cf_v4, &blocked_v4).map(|new_ip| (ip, new_ip)))
            .collect();
        let evasion_v6 = blocked_v6
            .iter()
            .filter_map(|&ip| scan_evasive_v6(ip, &cf_v6, &blocked_v6).map(|new_ip| (ip, new_ip)))
            .collect();
        Self {
            blocked_v4,
            blocked_v6,
            cf_v4,
            cf_v6,
            evasion_v4,
            evasion_v6,
        }
    }

    /// Reads the four list files. A file that cannot be read keeps the
    /// values from `previous` instead of silently switching evasion off.
    async fn load(paths: &Paths, previous: Option<&Data>) -> Self {
        let (v4, v6, cf4, cf6) = tokio::join!(
            read_lines(&paths.blocked_v4),
            read_lines(&paths.blocked_v6),
            read_lines(&paths.cf_v4),
            read_lines(&paths.cf_v6)
        );
        let blocked_v4 = match v4 {
            Some(lines) => lines
                .iter()
                .filter_map(|s| Ipv4Addr::from_str(s).ok())
                .map(u32::from)
                .collect(),
            None => previous.map(|p| p.blocked_v4.clone()).unwrap_or_default(),
        };
        let blocked_v6 = match v6 {
            Some(lines) => lines
                .iter()
                .filter_map(|s| Ipv6Addr::from_str(s).ok())
                .map(u128::from)
                .collect(),
            None => previous.map(|p| p.blocked_v6.clone()).unwrap_or_default(),
        };
        let cf_v4 = match cf4 {
            Some(lines) => merge_v4(lines.iter().filter_map(|s| parse_v4_prefix(s))),
            None => previous.map(|p| p.cf_v4.clone()).unwrap_or_default(),
        };
        let cf_v6 = match cf6 {
            Some(lines) => merge_v6(lines.iter().filter_map(|s| parse_v6_prefix(s))),
            None => previous.map(|p| p.cf_v6.clone()).unwrap_or_default(),
        };
        let data = Self::new(blocked_v4, blocked_v6, cf_v4, cf_v6);
        eprintln!(
            "loaded {} blocked IPv4, {} blocked IPv6, {} Cloudflare IPv4 intervals, {} IPv6 intervals",
            data.blocked_v4.len(), data.blocked_v6.len(), data.cf_v4.len(), data.cf_v6.len()
        );
        if data.cf_v4.is_empty() && data.cf_v6.is_empty() {
            eprintln!("warning: no Cloudflare prefixes loaded; evasion is disabled");
        }
        data
    }

    fn evasive_v4(&self, ip: u32) -> Option<u32> {
        self.evasion_v4.get(&ip).copied()
    }

    fn evasive_v6(&self, ip: u128) -> Option<u128> {
        self.evasion_v6.get(&ip).copied()
    }
}

fn scan_evasive_v4(ip: u32, cf_v4: &[(u32, u32)], blocked_v4: &HashSet<u32>) -> Option<u32> {
    let (start, end) = containing(cf_v4, ip)?;
    let base = ip & 0xffff_ff00;
    let last = (ip & 0xff) as i32;
    for offset in 1..255i32 {
        for candidate_last in [last + offset, last - offset] {
            if (1..=254).contains(&candidate_last) {
                let candidate = base | candidate_last as u32;
                if candidate >= start && candidate <= end && !blocked_v4.contains(&candidate) {
                    return Some(candidate);
                }
            }
        }
    }
    let max = u64::from(end - start).saturating_add(1).min(65_536) as u32;
    for offset in 1..max {
        for candidate in [ip.checked_add(offset), ip.checked_sub(offset)]
            .into_iter()
            .flatten()
        {
            let last = candidate & 0xff;
            if candidate >= start
                && candidate <= end
                && (1..=254).contains(&last)
                && !blocked_v4.contains(&candidate)
            {
                return Some(candidate);
            }
        }
    }
    None
}

fn scan_evasive_v6(ip: u128, cf_v6: &[(u128, u128)], blocked_v6: &HashSet<u128>) -> Option<u128> {
    let (start, end) = containing(cf_v6, ip)?;
    for offset in 1..1024u128 {
        for candidate in [ip.checked_add(offset), ip.checked_sub(offset)]
            .into_iter()
            .flatten()
        {
            if candidate >= start && candidate <= end && !blocked_v6.contains(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

#[derive(Default)]
struct Counters {
    evaded_queries: AtomicU64,
    evaded_records: AtomicU64,
    total_queries: AtomicU64,
    last_evaded_bits: AtomicU64,
    dropped_udp: AtomicU64,
    dropped_tcp: AtomicU64,
    upstream_failures_udp: AtomicU64,
    upstream_failures_tcp: AtomicU64,
    last_reload_bits: AtomicU64,
}

#[derive(Serialize, Deserialize, Default)]
struct StatsFile {
    evaded_queries_total: u64,
    evaded_records_total: u64,
    total_queries_processed: u64,
    last_evasion_timestamp: f64,
    #[serde(default)]
    last_updated: f64,
}

impl Counters {
    async fn load(path: &Path) -> Self {
        let parsed = match tokio::fs::read(path).await {
            Ok(bytes) => serde_json::from_slice::<StatsFile>(&bytes).unwrap_or_default(),
            Err(_) => StatsFile::default(),
        };
        Self {
            evaded_queries: AtomicU64::new(parsed.evaded_queries_total),
            evaded_records: AtomicU64::new(parsed.evaded_records_total),
            total_queries: AtomicU64::new(parsed.total_queries_processed),
            last_evaded_bits: AtomicU64::new(parsed.last_evasion_timestamp.to_bits()),
            ..Default::default()
        }
    }

    fn snapshot(&self) -> StatsFile {
        StatsFile {
            evaded_queries_total: self.evaded_queries.load(Relaxed),
            evaded_records_total: self.evaded_records.load(Relaxed),
            total_queries_processed: self.total_queries.load(Relaxed),
            last_evasion_timestamp: f64::from_bits(self.last_evaded_bits.load(Relaxed)),
            last_updated: epoch(),
        }
    }
}

struct Limits {
    udp: Arc<Semaphore>,
    tcp: Arc<Semaphore>,
    max_udp: usize,
    max_tcp: usize,
}

impl Limits {
    fn new(max_udp: usize, max_tcp: usize) -> Self {
        Self {
            udp: Arc::new(Semaphore::new(max_udp)),
            tcp: Arc::new(Semaphore::new(max_tcp)),
            max_udp,
            max_tcp,
        }
    }

    fn from_env() -> Self {
        fn value(name: &str, default: usize) -> usize {
            std::env::var(name)
                .ok()
                .and_then(|v| v.trim().parse().ok())
                .filter(|&v| v > 0)
                .unwrap_or(default)
        }
        Self::new(
            value("EVADE_MAX_INFLIGHT_UDP", DEFAULT_MAX_INFLIGHT_UDP),
            value("EVADE_MAX_INFLIGHT_TCP", DEFAULT_MAX_INFLIGHT_TCP),
        )
    }

    fn inflight_udp(&self) -> usize {
        self.max_udp - self.udp.available_permits()
    }

    fn inflight_tcp(&self) -> usize {
        self.max_tcp - self.tcp.available_permits()
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_INFLIGHT_UDP, DEFAULT_MAX_INFLIGHT_TCP)
    }
}

struct App {
    data: RwLock<Arc<Data>>,
    counters: Counters,
    paths: Paths,
    test_redirects: HashMap<String, TestRedirect>,
    temporary_redirects: RwLock<Arc<HashMap<String, TestRedirect>>>,
    limits: Limits,
}

impl App {
    async fn new(paths: Paths, test_redirects: HashMap<String, TestRedirect>) -> Arc<Self> {
        let data = Data::load(&paths, None).await;
        let counters = Counters::load(&paths.stats).await;
        counters.last_reload_bits.store(epoch().to_bits(), Relaxed);
        let temporary_redirects = load_temporary_redirects(&paths.redirects).await;
        Arc::new(Self {
            data: RwLock::new(Arc::new(data)),
            counters,
            paths,
            test_redirects,
            temporary_redirects: RwLock::new(Arc::new(temporary_redirects)),
            limits: Limits::from_env(),
        })
    }

    fn active_redirect<'a>(
        &'a self,
        packet: &[u8],
        temporary_redirects: &'a HashMap<String, TestRedirect>,
    ) -> Option<&'a TestRedirect> {
        // Decoding the question name allocates (labels, lowercasing, join). Only pay
        // for it when some redirect rule actually exists — in production neither map
        // is populated most of the time, so this is skipped on the common path.
        if self.test_redirects.is_empty() && temporary_redirects.is_empty() {
            return None;
        }
        question_name(packet)
            .and_then(|domain| {
                self.test_redirects
                    .get(&domain)
                    .or_else(|| temporary_redirects.get(&domain))
            })
            .filter(|redirect| redirect.expires_at.is_none_or(|expires| expires > epoch()))
    }

    /// Entry point for upstream responses: may shrink the packet (see
    /// `suppress_unverified_family`), otherwise rewrites it in place.
    fn process(&self, packet: &mut Vec<u8>) -> usize {
        if let Some(removed) = self.suppress_unverified_family(packet) {
            return removed;
        }
        self.rewrite(packet)
    }

    /// While a redirect pins only an IPv4 address, answer AAAA and HTTPS/SVCB
    /// with an empty NOERROR. Otherwise a dual-stack client would take the
    /// untested (possibly blocked) IPv6 path and skip the verified IPv4 one:
    /// AAAA directly, HTTPS through its ipv6hint, which cannot be removed in
    /// place. Without HTTPS the browser falls back to the redirected A record.
    /// There is no SOA, so resolvers do not cache the empty answer.
    fn suppress_unverified_family(&self, packet: &mut Vec<u8>) -> Option<usize> {
        let temporary_redirects = self
            .temporary_redirects
            .read()
            .expect("redirect lock poisoned")
            .clone();
        let redirect = self.active_redirect(packet, &temporary_redirects)?;
        if redirect.v4.is_none() || redirect.v6.is_some() {
            return None;
        }
        let question_end = skip_name(packet, 12)?.checked_add(4)?;
        let qtype = be16(packet, question_end - 4)?;
        let rcode = packet.get(3)? & 0x0f;
        let answers = be16(packet, 6)? as usize;
        if !matches!(qtype, 28 | 64 | 65) || rcode != 0 || answers == 0 {
            return None;
        }
        let records = resource_records(packet)?;
        let mut out = packet.get(..question_end)?.to_vec();
        // Keep the EDNS OPT pseudo-record (root name, no compression pointers).
        let mut additional = 0u16;
        for rr in records.iter().filter(|rr| rr.kind == 41) {
            out.extend_from_slice(&packet[rr.start..rr.rdata + rr.rdlen]);
            additional += 1;
        }
        out[6..8].copy_from_slice(&0u16.to_be_bytes());
        out[8..10].copy_from_slice(&0u16.to_be_bytes());
        out[10..12].copy_from_slice(&additional.to_be_bytes());
        out[3] &= !0x20; // not validated data any more
        *packet = out;
        self.counters.total_queries.fetch_add(1, Relaxed);
        self.counters.evaded_queries.fetch_add(1, Relaxed);
        self.counters
            .evaded_records
            .fetch_add(answers as u64, Relaxed);
        self.counters
            .last_evaded_bits
            .store(epoch().to_bits(), Relaxed);
        Some(answers)
    }

    fn rewrite(&self, packet: &mut [u8]) -> usize {
        self.counters.total_queries.fetch_add(1, Relaxed);
        let data = self.data.read().expect("data lock poisoned").clone();
        let temporary_redirects = self
            .temporary_redirects
            .read()
            .expect("redirect lock poisoned")
            .clone();
        let test_redirect = self.active_redirect(packet, &temporary_redirects);
        let records = match resource_records(packet) {
            Some(records) => records,
            None => return 0,
        };
        let mut changes: Vec<(usize, Vec<u8>)> = Vec::new();
        let mut has_cloudflare = false;
        for rr in &records {
            // Inspect original addresses even when a temporary redirect applies.
            match (rr.kind, rr.rdlen) {
                (1, 4) => {
                    let ip = u32::from_be_bytes(packet[rr.rdata..rr.rdata + 4].try_into().unwrap());
                    has_cloudflare |= containing(&data.cf_v4, ip).is_some();
                }
                (28, 16) => {
                    let ip =
                        u128::from_be_bytes(packet[rr.rdata..rr.rdata + 16].try_into().unwrap());
                    has_cloudflare |= containing(&data.cf_v6, ip).is_some();
                }
                _ => {}
            }
            if rr.answer {
                match (rr.kind, rr.rdlen, test_redirect) {
                    (1, 4, Some(redirect)) => {
                        if let Some(ip) = redirect.v4 {
                            let bytes = ip.to_be_bytes();
                            if packet[rr.rdata..rr.rdata + 4] != bytes {
                                changes.push((rr.rdata, bytes.to_vec()));
                            }
                            continue;
                        }
                    }
                    (28, 16, Some(redirect)) => {
                        if let Some(ip) = redirect.v6 {
                            let bytes = ip.to_be_bytes();
                            if packet[rr.rdata..rr.rdata + 16] != bytes {
                                changes.push((rr.rdata, bytes.to_vec()));
                            }
                            continue;
                        }
                    }
                    _ => {}
                }
            }
            match (rr.kind, rr.rdlen) {
                (1, 4) => {
                    let ip = u32::from_be_bytes(packet[rr.rdata..rr.rdata + 4].try_into().unwrap());
                    if data.blocked_v4.contains(&ip) {
                        if let Some(new_ip) = data.evasive_v4(ip) {
                            changes.push((rr.rdata, new_ip.to_be_bytes().to_vec()));
                        }
                    }
                }
                (28, 16) => {
                    let ip =
                        u128::from_be_bytes(packet[rr.rdata..rr.rdata + 16].try_into().unwrap());
                    if data.blocked_v6.contains(&ip) {
                        if let Some(new_ip) = data.evasive_v6(ip) {
                            changes.push((rr.rdata, new_ip.to_be_bytes().to_vec()));
                        }
                    }
                }
                (64, _) | (65, _) => {
                    let redirect = if rr.answer { test_redirect } else { None };
                    changes.extend(svcb_hint_changes(
                        packet,
                        rr,
                        data.as_ref(),
                        redirect,
                        &mut has_cloudflare,
                    ));
                }
                _ => {}
            }
        }
        if has_cloudflare || !changes.is_empty() {
            let limit = match (has_cloudflare, changes.is_empty()) {
                (true, true) => CLOUDFLARE_MAX_TTL,
                (true, false) => CLOUDFLARE_MAX_TTL.min(self.paths.rewrite_ttl),
                _ => self.paths.rewrite_ttl,
            };
            // Cap the whole response consistently, including mixed RRsets and
            // aliases, but never raise a shorter TTL or modify pseudo-records.
            for rr in &records {
                if matches!(rr.kind, 41 | 249 | 250) {
                    continue;
                }
                let old = u32::from_be_bytes(packet[rr.ttl..rr.ttl + 4].try_into().unwrap());
                packet[rr.ttl..rr.ttl + 4].copy_from_slice(&old.min(limit).to_be_bytes());
            }
        }
        // TTL-only changes are not IP evasion events.
        if changes.is_empty() {
            return 0;
        }
        for (offset, bytes) in &changes {
            packet[*offset..*offset + bytes.len()].copy_from_slice(bytes);
        }
        // The rewritten addresses no longer match their RRSIGs: stop claiming
        // the answer was DNSSEC-validated (AD flag, header byte 3, bit 0x20).
        if let Some(flags) = packet.get_mut(3) {
            *flags &= !0x20;
        }
        let count = changes.len();
        self.counters.evaded_queries.fetch_add(1, Relaxed);
        self.counters
            .evaded_records
            .fetch_add(count as u64, Relaxed);
        self.counters
            .last_evaded_bits
            .store(epoch().to_bits(), Relaxed);
        count
    }
}

#[derive(Clone, Copy)]
struct Record {
    start: usize,
    kind: u16,
    ttl: usize,
    rdlen: usize,
    rdata: usize,
    answer: bool,
}

fn resource_records(packet: &[u8]) -> Option<Vec<Record>> {
    if packet.len() < 12 {
        return None;
    }
    let qd = be16(packet, 4)? as usize;
    let answers = be16(packet, 6)? as usize;
    let total = answers + be16(packet, 8)? as usize + be16(packet, 10)? as usize;
    let mut pos = 12;
    for _ in 0..qd {
        pos = skip_name(packet, pos)?;
        pos = pos.checked_add(4)?;
        if pos > packet.len() {
            return None;
        }
    }
    let mut records = Vec::with_capacity(total);
    for index in 0..total {
        let start = pos;
        pos = skip_name(packet, pos)?;
        if pos.checked_add(10)? > packet.len() {
            return None;
        }
        let kind = be16(packet, pos)?;
        let ttl = pos + 4;
        let rdlen = be16(packet, pos + 8)? as usize;
        let rdata = pos + 10;
        pos = rdata.checked_add(rdlen)?;
        if pos > packet.len() {
            return None;
        }
        records.push(Record {
            start,
            kind,
            ttl,
            rdlen,
            rdata,
            answer: index < answers,
        });
    }
    Some(records)
}

// Rewrite ipv4hint (SvcParamKey 4) and ipv6hint (SvcParamKey 6) inside an
// HTTPS (type 65) or SVCB (type 64) record. Modern browsers connect straight to
// the address in these hints, bypassing the A/AAAA record entirely, so the same
// block-evasion logic must apply here. Hints are rewritten in place (same width),
// so no packet resizing is needed. Returns (offset, new_bytes) edits.
fn svcb_hint_changes(
    packet: &[u8],
    rr: &Record,
    data: &Data,
    test_redirect: Option<&TestRedirect>,
    has_cloudflare: &mut bool,
) -> Vec<(usize, Vec<u8>)> {
    let mut changes = Vec::new();
    let end = match rr.rdata.checked_add(rr.rdlen) {
        Some(end) if end <= packet.len() => end,
        _ => return changes,
    };
    // SvcPriority (2 bytes)
    let mut pos = match rr.rdata.checked_add(2) {
        Some(p) if p <= end => p,
        _ => return changes,
    };
    // TargetName: uncompressed per RFC 9460. Bail on any compression pointer.
    loop {
        if pos >= end {
            return changes;
        }
        let n = packet[pos];
        if n & 0xc0 != 0 {
            return changes;
        }
        pos += 1;
        if n == 0 {
            break;
        }
        match pos.checked_add(n as usize) {
            Some(p) if p <= end => pos = p,
            _ => return changes,
        }
    }
    // SvcParams: repeated { key(2) len(2) value(len) }, keys ascending.
    while pos + 4 <= end {
        let key = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let vlen = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]) as usize;
        pos += 4;
        let vend = match pos.checked_add(vlen) {
            Some(v) if v <= end => v,
            _ => break,
        };
        match key {
            4 => {
                let mut off = pos;
                while off + 4 <= vend {
                    let ip = u32::from_be_bytes(packet[off..off + 4].try_into().unwrap());
                    *has_cloudflare |= containing(&data.cf_v4, ip).is_some();
                    let new = test_redirect.and_then(|r| r.v4).or_else(|| {
                        if data.blocked_v4.contains(&ip) {
                            data.evasive_v4(ip)
                        } else {
                            None
                        }
                    });
                    if let Some(new_ip) = new {
                        let bytes = new_ip.to_be_bytes();
                        if packet[off..off + 4] != bytes {
                            changes.push((off, bytes.to_vec()));
                        }
                    }
                    off += 4;
                }
            }
            6 => {
                let mut off = pos;
                while off + 16 <= vend {
                    let ip = u128::from_be_bytes(packet[off..off + 16].try_into().unwrap());
                    *has_cloudflare |= containing(&data.cf_v6, ip).is_some();
                    let new = test_redirect.and_then(|r| r.v6).or_else(|| {
                        if data.blocked_v6.contains(&ip) {
                            data.evasive_v6(ip)
                        } else {
                            None
                        }
                    });
                    if let Some(new_ip) = new {
                        let bytes = new_ip.to_be_bytes();
                        if packet[off..off + 16] != bytes {
                            changes.push((off, bytes.to_vec()));
                        }
                    }
                    off += 16;
                }
            }
            _ => {}
        }
        pos = vend;
    }
    changes
}

fn question_name(packet: &[u8]) -> Option<String> {
    if be16(packet, 4)? == 0 {
        return None;
    }
    let (name, _) = decode_name(packet, 12)?;
    Some(name)
}

fn decode_name(packet: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut pos = start;
    let mut end = None;
    let mut jumps = 0usize;
    loop {
        let n = *packet.get(pos)?;
        if n & 0xc0 == 0xc0 {
            let low = *packet.get(pos + 1)? as usize;
            let target = (((n & 0x3f) as usize) << 8) | low;
            end.get_or_insert(pos.checked_add(2)?);
            pos = target;
            jumps += 1;
            if jumps > 128 {
                return None;
            }
            continue;
        }
        if n & 0xc0 != 0 || n > 63 {
            return None;
        }
        pos = pos.checked_add(1)?;
        if n == 0 {
            let consumed = end.unwrap_or(pos);
            return Some((labels.join("."), consumed));
        }
        let label = packet.get(pos..pos.checked_add(n as usize)?)?;
        labels.push(std::str::from_utf8(label).ok()?.to_ascii_lowercase());
        pos += n as usize;
    }
}

fn skip_name(packet: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let n = *packet.get(pos)?;
        if n & 0xc0 == 0xc0 {
            packet.get(pos + 1)?;
            return pos.checked_add(2);
        }
        if n & 0xc0 != 0 || n > 63 {
            return None;
        }
        pos = pos.checked_add(1)?;
        if n == 0 {
            return Some(pos);
        }
        pos = pos.checked_add(n as usize)?;
        if pos > packet.len() {
            return None;
        }
    }
}

fn be16(bytes: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        bytes.get(pos..pos + 2)?.try_into().ok()?,
    ))
}

async fn udp_server(app: Arc<App>, listen: u16, upstream: u16) -> Result<()> {
    let socket = Arc::new(UdpSocket::bind((LISTEN_HOST, listen)).await?);
    let upstream: SocketAddr = format!("{UPSTREAM_HOST}:{upstream}").parse()?;
    eprintln!("DNS UDP {LISTEN_HOST}:{listen} -> {upstream}");
    serve_udp(app, socket, upstream).await
}

async fn serve_udp(app: Arc<App>, socket: Arc<UdpSocket>, upstream: SocketAddr) -> Result<()> {
    // One receive buffer for the listener; each query is copied out at its real
    // size, so a query waiting on Unbound no longer pins 64 KiB.
    let mut buffer = vec![0u8; UDP_LIMIT];
    loop {
        let (len, peer) = socket.recv_from(&mut buffer).await?;
        let Ok(slot) = app.limits.udp.clone().try_acquire_owned() else {
            app.counters.dropped_udp.fetch_add(1, Relaxed);
            continue;
        };
        let query = buffer[..len].to_vec();
        let app = app.clone();
        let socket = socket.clone();
        tokio::spawn(async move {
            let _slot = slot;
            match forward_udp(&query, upstream).await {
                Some(mut response) => {
                    app.process(&mut response);
                    let _ = socket.send_to(&response, peer).await;
                }
                None => {
                    app.counters.upstream_failures_udp.fetch_add(1, Relaxed);
                }
            }
        });
    }
}

async fn forward_udp(query: &[u8], upstream: SocketAddr) -> Option<Vec<u8>> {
    let up = UdpSocket::bind((LISTEN_HOST, 0)).await.ok()?;
    up.connect(upstream).await.ok()?;
    up.send(query).await.ok()?;
    timeout(UPSTREAM_TIMEOUT, async {
        loop {
            up.readable().await.ok()?;
            match recv_exact(&up) {
                Ok(response) => return Some(response),
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                Err(_) => return None,
            }
        }
    })
    .await
    .ok()?
}

/// Reads one datagram through a per-thread 64 KiB scratch buffer and returns
/// only the bytes received. Synchronous on purpose: the scratch buffer never
/// becomes part of a suspended task.
fn recv_exact(socket: &UdpSocket) -> io::Result<Vec<u8>> {
    thread_local! {
        static SCRATCH: RefCell<Box<[u8]>> = RefCell::new(vec![0; UDP_LIMIT].into_boxed_slice());
    }
    SCRATCH.with_borrow_mut(|scratch| socket.try_recv(scratch).map(|len| scratch[..len].to_vec()))
}

async fn tcp_server(app: Arc<App>, listen: u16, upstream: u16) -> Result<()> {
    let listener = TcpListener::bind((LISTEN_HOST, listen)).await?;
    let upstream: SocketAddr = format!("{UPSTREAM_HOST}:{upstream}").parse()?;
    eprintln!("DNS TCP {LISTEN_HOST}:{listen} -> {upstream}");
    serve_tcp(app, listener, upstream).await
}

async fn serve_tcp(app: Arc<App>, listener: TcpListener, upstream: SocketAddr) -> Result<()> {
    loop {
        let (client, _) = listener.accept().await?;
        let Ok(slot) = app.limits.tcp.clone().try_acquire_owned() else {
            app.counters.dropped_tcp.fetch_add(1, Relaxed);
            continue; // dropping `client` closes the connection
        };
        let app = app.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let _ = handle_tcp(app, client, upstream).await;
        });
    }
}

/// Answers every query the client sends on this connection, in order, over a
/// single upstream connection (RFC 7766), until the client goes idle.
async fn handle_tcp(app: Arc<App>, mut client: TcpStream, upstream: SocketAddr) -> Result<()> {
    let mut upstream_conn: Option<TcpStream> = None;
    loop {
        let len = match timeout(TCP_IDLE, client.read_u16()).await {
            Ok(Ok(len)) => len as usize,
            _ => return Ok(()), // idle, closed by the client, or broken
        };
        let mut query = vec![0; len];
        timeout(UPSTREAM_TIMEOUT, client.read_exact(&mut query)).await??;
        let mut response = match exchange_tcp(&mut upstream_conn, upstream, &query).await {
            Ok(response) => response,
            Err(err) => {
                app.counters.upstream_failures_tcp.fetch_add(1, Relaxed);
                return Err(err);
            }
        };
        app.process(&mut response);
        client.write_all(&tcp_frame(&response)).await?;
    }
}

async fn exchange_tcp(
    conn: &mut Option<TcpStream>,
    upstream: SocketAddr,
    query: &[u8],
) -> Result<Vec<u8>> {
    loop {
        // Unbound may close a reused connection while it sits idle; that
        // deserves one retry on a fresh connection. A fresh failure or a
        // timeout (Unbound dropped the query) does not: retrying would only
        // double the wait.
        let reused = conn.is_some();
        if !reused {
            *conn = Some(timeout(UPSTREAM_TIMEOUT, TcpStream::connect(upstream)).await??);
        }
        let stream = conn.as_mut().expect("connection just set");
        match tcp_roundtrip(stream, query).await {
            Ok(response) => return Ok(response),
            Err(err) => {
                *conn = None;
                if !reused || err.is::<tokio::time::error::Elapsed>() {
                    return Err(err);
                }
            }
        }
    }
}

async fn tcp_roundtrip(stream: &mut TcpStream, query: &[u8]) -> Result<Vec<u8>> {
    stream.write_all(&tcp_frame(query)).await?;
    let len = timeout(UPSTREAM_TIMEOUT, stream.read_u16()).await?? as usize;
    let mut response = vec![0; len];
    timeout(UPSTREAM_TIMEOUT, stream.read_exact(&mut response)).await??;
    Ok(response)
}

/// Length-prefixed DNS message, sent in a single write.
fn tcp_frame(message: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(message.len() + 2);
    frame.extend_from_slice(&(message.len() as u16).to_be_bytes());
    frame.extend_from_slice(message);
    frame
}

async fn metrics_server(app: Arc<App>, port: u16) -> Result<()> {
    let listener = TcpListener::bind((LISTEN_HOST, port)).await?;
    eprintln!("metrics HTTP {LISTEN_HOST}:{port}");
    loop {
        let (stream, _) = listener.accept().await?;
        let app = app.clone();
        tokio::spawn(async move {
            let _ = handle_http(app, stream).await;
        });
    }
}

async fn handle_http(app: Arc<App>, stream: TcpStream) -> Result<()> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    timeout(Duration::from_secs(2), reader.read_line(&mut line)).await??;
    let metrics = line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .starts_with("/metrics");
    loop {
        line.clear();
        if timeout(Duration::from_secs(1), reader.read_line(&mut line)).await?? == 0
            || line == "\r\n"
            || line == "\n"
        {
            break;
        }
    }
    let stats = app.counters.snapshot();
    let (kind, body) = if metrics {
        ("text/plain; version=0.0.4", metrics_body(&app, &stats))
    } else {
        ("application/json", serde_json::to_string_pretty(&stats)?)
    };
    let response = format!("HTTP/1.1 200 OK\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    reader.get_mut().write_all(response.as_bytes()).await?;
    Ok(())
}

fn metrics_body(app: &App, stats: &StatsFile) -> String {
    use std::fmt::Write;
    let data = app.data.read().expect("data lock poisoned").clone();
    let redirects = app
        .temporary_redirects
        .read()
        .expect("redirect lock poisoned")
        .len();
    let c = &app.counters;
    let mut out = String::new();
    let mut metric = |name: &str, kind: &str, help: &str, samples: &[(&str, String)]| {
        let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
        for (labels, value) in samples {
            let _ = writeln!(out, "{name}{labels} {value}");
        }
    };
    let one = |v: String| [("", v)];
    metric(
        "xdp_evade_queries_total",
        "counter",
        "Total DNS queries rewritten for block evasion",
        &one(stats.evaded_queries_total.to_string()),
    );
    metric(
        "xdp_evade_records_total",
        "counter",
        "Total DNS records replaced for block evasion",
        &one(stats.evaded_records_total.to_string()),
    );
    metric(
        "xdp_evade_queries_processed",
        "counter",
        "Total queries processed by evasion proxy",
        &one(stats.total_queries_processed.to_string()),
    );
    metric(
        "xdp_evade_dropped_total",
        "counter",
        "Queries dropped because the in-flight limit was reached",
        &[
            ("{proto=\"udp\"}", c.dropped_udp.load(Relaxed).to_string()),
            ("{proto=\"tcp\"}", c.dropped_tcp.load(Relaxed).to_string()),
        ],
    );
    metric(
        "xdp_evade_inflight",
        "gauge",
        "Queries currently waiting on the upstream resolver",
        &[
            ("{proto=\"udp\"}", app.limits.inflight_udp().to_string()),
            ("{proto=\"tcp\"}", app.limits.inflight_tcp().to_string()),
        ],
    );
    metric(
        "xdp_evade_upstream_failures_total",
        "counter",
        "Queries that got no answer from the upstream resolver",
        &[
            (
                "{proto=\"udp\"}",
                c.upstream_failures_udp.load(Relaxed).to_string(),
            ),
            (
                "{proto=\"tcp\"}",
                c.upstream_failures_tcp.load(Relaxed).to_string(),
            ),
        ],
    );
    metric(
        "xdp_evade_blocked_ips",
        "gauge",
        "Addresses in the loaded blocklists",
        &[
            ("{family=\"ipv4\"}", data.blocked_v4.len().to_string()),
            ("{family=\"ipv6\"}", data.blocked_v6.len().to_string()),
        ],
    );
    metric(
        "xdp_evade_evadable_ips",
        "gauge",
        "Blocked addresses with a free neighbour to jump to",
        &[
            ("{family=\"ipv4\"}", data.evasion_v4.len().to_string()),
            ("{family=\"ipv6\"}", data.evasion_v6.len().to_string()),
        ],
    );
    metric(
        "xdp_evade_cloudflare_ranges",
        "gauge",
        "Merged Cloudflare ranges eligible for rewriting",
        &[
            ("{family=\"ipv4\"}", data.cf_v4.len().to_string()),
            ("{family=\"ipv6\"}", data.cf_v6.len().to_string()),
        ],
    );
    metric(
        "xdp_evade_active_redirects",
        "gauge",
        "Temporary redirects set by the residential probe",
        &one(redirects.to_string()),
    );
    metric(
        "xdp_evade_last_reload_timestamp_seconds",
        "gauge",
        "When the lists were last (re)loaded",
        &one(format!(
            "{:.0}",
            f64::from_bits(c.last_reload_bits.load(Relaxed))
        )),
    );
    out
}

async fn maintenance(app: Arc<App>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    let mut ticks = 0u8;
    // None forces one reload on the first pass, covering changes made while
    // App::new was loading.
    let mut stamps: Option<[FileStamp; 4]> = None;
    loop {
        ticker.tick().await;
        let redirects = load_temporary_redirects(&app.paths.redirects).await;
        let changed = app
            .temporary_redirects
            .read()
            .expect("redirect lock poisoned")
            .as_ref()
            != &redirects;
        if changed {
            eprintln!("loaded {} active temporary redirect(s)", redirects.len());
            *app.temporary_redirects
                .write()
                .expect("redirect lock poisoned") = Arc::new(redirects);
        }

        ticks = ticks.wrapping_add(1);
        if ticks % 5 == 0 {
            let current = list_stamps(&app.paths).await;
            if stamps.as_ref() != Some(&current) {
                let previous = app.data.read().expect("data lock poisoned").clone();
                let new_data = Data::load(&app.paths, Some(&previous)).await;
                *app.data.write().expect("data lock poisoned") = Arc::new(new_data);
                app.counters
                    .last_reload_bits
                    .store(epoch().to_bits(), Relaxed);
                stamps = Some(current);
            }
            if let Err(err) = save_stats(&app.paths.stats, &app.counters.snapshot()).await {
                eprintln!("warning: could not persist stats: {err:#}");
            }
        }
    }
}

async fn load_temporary_redirects(path: &Path) -> HashMap<String, TestRedirect> {
    let text = tokio::fs::read_to_string(path).await.unwrap_or_default();
    parse_temporary_redirects(&text, epoch())
}

fn parse_temporary_redirects(text: &str, now: f64) -> HashMap<String, TestRedirect> {
    let mut redirects = HashMap::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(rule) = parts.next() else { continue };
        let Some(expires_text) = parts.next() else {
            eprintln!("warning: redirect without expiry ignored: {line}");
            continue;
        };
        if parts.next().is_some() {
            eprintln!("warning: invalid redirect line ignored: {line}");
            continue;
        }
        let Ok(expires_at) = expires_text.parse::<f64>() else {
            eprintln!("warning: invalid redirect expiry ignored: {line}");
            continue;
        };
        if expires_at <= now {
            continue;
        }
        if let Err(error) = add_redirect(&mut redirects, rule) {
            eprintln!("warning: invalid temporary redirect ignored: {error:#}");
            continue;
        }
        if let Some((domain, _)) = rule.split_once('=') {
            if let Ok(domain) = normalize_domain(domain) {
                if let Some(redirect) = redirects.get_mut(&domain) {
                    redirect.expires_at = Some(expires_at);
                }
            }
        }
    }
    redirects
}

async fn save_stats(path: &Path, stats: &StatsFile) -> Result<()> {
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(stats)?;
    tokio::fs::write(&tmp, bytes)
        .await
        .with_context(|| format!("write {}", tmp.display()))?;
    tokio::fs::rename(&tmp, path)
        .await
        .with_context(|| format!("rename {}", path.display()))?;
    Ok(())
}

async fn read_lines(path: &Path) -> Option<Vec<String>> {
    match tokio::fs::read_to_string(path).await {
        Ok(text) => Some(
            text.lines()
                .map(str::trim)
                .filter(|s| !s.is_empty() && !s.starts_with('#'))
                .map(str::to_owned)
                .collect(),
        ),
        Err(err) => {
            eprintln!(
                "warning: cannot read {}: {err}; keeping previous entries",
                path.display()
            );
            None
        }
    }
}

/// Modification time and size of a list file, or None if it cannot be read.
/// The lists are only re-parsed when one of these changes.
type FileStamp = Option<(SystemTime, u64)>;

async fn file_stamp(path: &Path) -> FileStamp {
    let meta = tokio::fs::metadata(path).await.ok()?;
    Some((meta.modified().ok()?, meta.len()))
}

async fn list_stamps(paths: &Paths) -> [FileStamp; 4] {
    let (a, b, c, d) = tokio::join!(
        file_stamp(&paths.blocked_v4),
        file_stamp(&paths.blocked_v6),
        file_stamp(&paths.cf_v4),
        file_stamp(&paths.cf_v6)
    );
    [a, b, c, d]
}

fn parse_v4_prefix(text: &str) -> Option<(u32, u32)> {
    let (ip, bits) = split_prefix::<Ipv4Addr>(text, 32)?;
    let bits = bits as u32;
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    let start = u32::from(ip) & mask;
    Some((start, start | !mask))
}

fn parse_v6_prefix(text: &str) -> Option<(u128, u128)> {
    let (ip, bits) = split_prefix::<Ipv6Addr>(text, 128)?;
    let bits = bits as u32;
    let mask = if bits == 0 {
        0
    } else {
        u128::MAX << (128 - bits)
    };
    let start = u128::from(ip) & mask;
    Some((start, start | !mask))
}

fn split_prefix<T: FromStr>(text: &str, max: u8) -> Option<(T, u8)> {
    let (ip, bits) = text.split_once('/').unwrap_or((text, ""));
    let bits = if bits.is_empty() {
        max
    } else {
        bits.parse().ok()?
    };
    if bits > max {
        return None;
    }
    Some((ip.parse().ok()?, bits))
}

fn merge_v4(items: impl Iterator<Item = (u32, u32)>) -> Vec<(u32, u32)> {
    merge(items.collect())
}
fn merge_v6(items: impl Iterator<Item = (u128, u128)>) -> Vec<(u128, u128)> {
    merge(items.collect())
}

fn merge<T>(mut ranges: Vec<(T, T)>) -> Vec<(T, T)>
where
    T: Copy + Ord + CheckedAddOne,
{
    ranges.sort_unstable();
    let mut out: Vec<(T, T)> = Vec::new();
    for (start, end) in ranges {
        if let Some(last) = out.last_mut() {
            if start <= last.1 || last.1.checked_add_one().is_some_and(|next| start <= next) {
                if end > last.1 {
                    last.1 = end;
                }
                continue;
            }
        }
        out.push((start, end));
    }
    out
}

trait CheckedAddOne: Sized {
    fn checked_add_one(self) -> Option<Self>;
}
impl CheckedAddOne for u32 {
    fn checked_add_one(self) -> Option<Self> {
        self.checked_add(1)
    }
}
impl CheckedAddOne for u128 {
    fn checked_add_one(self) -> Option<Self> {
        self.checked_add(1)
    }
}

fn containing<T: Copy + Ord>(ranges: &[(T, T)], value: T) -> Option<(T, T)> {
    let index = ranges
        .partition_point(|(start, _)| *start <= value)
        .checked_sub(1)?;
    let range = ranges[index];
    (value <= range.1).then_some(range)
}

fn epoch() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = RuntimeConfig::parse()?;
    let paths = Paths::from_env(config.test_mode);
    if config.test_mode {
        eprintln!(
            "TEST MODE: redirects={}, stats={}",
            config.redirects.len(),
            paths.stats.display()
        );
    }
    let port_pairs = config.port_pairs();
    let metrics_port = config.metrics_port();
    let app = App::new(paths, config.redirects).await;
    let maintenance_task = tokio::spawn(maintenance(app.clone()));
    let mut servers = tokio::task::JoinSet::new();
    for &(listen, upstream) in port_pairs {
        servers.spawn(udp_server(app.clone(), listen, upstream));
        servers.spawn(tcp_server(app.clone(), listen, upstream));
    }
    servers.spawn(metrics_server(app.clone(), metrics_port));

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        signal = tokio::signal::ctrl_c() => signal?,
        _ = sigterm.recv() => {}
        result = servers.join_next() => match result {
            Some(Ok(Err(error))) => return Err(error),
            Some(Err(error)) => return Err(error.into()),
            Some(Ok(Ok(()))) => bail!("a server task stopped unexpectedly"),
            None => bail!("all server tasks stopped unexpectedly"),
        }
    }
    maintenance_task.abort();
    // systemd stops the service with SIGTERM: keep the counters of the last
    // few seconds instead of losing them.
    if let Err(err) = save_stats(&app.paths.stats, &app.counters.snapshot()).await {
        eprintln!("warning: could not persist stats: {err:#}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preventive_app() -> App {
        let data = Data {
            cf_v4: vec![parse_v4_prefix("104.16.0.0/12").unwrap()],
            cf_v6: vec![parse_v6_prefix("2606:4700::/32").unwrap()],
            ..Default::default()
        };
        let mut paths = Paths::from_env(true);
        paths.rewrite_ttl = DEFAULT_REWRITE_TTL;
        App {
            data: RwLock::new(Arc::new(data)),
            counters: Counters::default(),
            paths,
            test_redirects: HashMap::new(),
            temporary_redirects: RwLock::new(Arc::new(HashMap::new())),
            limits: Limits::default(),
        }
    }

    fn answer_packet(kind: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, 0x81, 0xa0, 0, 1, 0, 1, 0, 0, 0, 0, 1, b'a', 3, b'c', b'o', b'm', 0,
        ];
        packet.extend(kind.to_be_bytes());
        packet.extend([0, 1, 0xc0, 0x0c]);
        packet.extend(kind.to_be_bytes());
        packet.extend([0, 1]);
        packet.extend(ttl.to_be_bytes());
        packet.extend((rdata.len() as u16).to_be_bytes());
        packet.extend(rdata);
        packet
    }

    // Mirrors a list reload: the neighbour map is rebuilt, not patched in place.
    fn block_v4(app: &App, ip: [u8; 4]) {
        let mut data = app.data.write().unwrap();
        let mut blocked_v4 = data.blocked_v4.clone();
        blocked_v4.insert(u32::from_be_bytes(ip));
        *data = Arc::new(Data::new(
            blocked_v4,
            data.blocked_v6.clone(),
            data.cf_v4.clone(),
            data.cf_v6.clone(),
        ));
    }

    fn ttl_of(packet: &[u8], index: usize) -> u32 {
        let rr = resource_records(packet).unwrap()[index];
        u32::from_be_bytes(packet[rr.ttl..rr.ttl + 4].try_into().unwrap())
    }

    #[test]
    fn caps_unblocked_cloudflare_a_and_aaaa_without_counting_evasion() {
        let app = preventive_app();
        for (kind, address) in [
            (1, vec![104, 16, 1, 1]),
            (
                28,
                "2606:4700::1111"
                    .parse::<Ipv6Addr>()
                    .unwrap()
                    .octets()
                    .to_vec(),
            ),
        ] {
            let mut packet = answer_packet(kind, 300, &address);
            let mut expected = packet.clone();
            let rr = resource_records(&packet).unwrap()[0];
            expected[rr.ttl..rr.ttl + 4].copy_from_slice(&30u32.to_be_bytes());
            assert_eq!(app.rewrite(&mut packet), 0);
            assert_eq!(packet, expected); // IP, flags (including AD), and RDATA preserved.
        }
        assert_eq!(app.counters.evaded_queries.load(Relaxed), 0);
        assert_eq!(app.counters.evaded_records.load(Relaxed), 0);
        assert_eq!(app.counters.total_queries.load(Relaxed), 2);
    }

    #[test]
    fn caps_unblocked_https_and_svcb_v4_and_v6_hints() {
        let app = preventive_app();
        for kind in [64, 65] {
            for (key, hint) in [
                (4u16, vec![104, 16, 1, 1]),
                (
                    6u16,
                    "2606:4700::1111"
                        .parse::<Ipv6Addr>()
                        .unwrap()
                        .octets()
                        .to_vec(),
                ),
            ] {
                let mut rdata = vec![0, 1, 0];
                rdata.extend(key.to_be_bytes());
                rdata.extend((hint.len() as u16).to_be_bytes());
                rdata.extend(hint);
                let mut packet = answer_packet(kind, 300, &rdata);
                assert_eq!(app.rewrite(&mut packet), 0);
                assert_eq!(ttl_of(&packet, 0), 30);
                assert!(packet.ends_with(&rdata));
            }
        }
    }

    #[test]
    fn never_raises_ttl_even_when_rewriting() {
        let app = preventive_app();
        for blocked in [false, true] {
            if blocked {
                block_v4(&app, [104, 16, 1, 1]);
            }
            for ttl in [0u32, 1, 5, 29, 30, 31, 300] {
                let mut packet = answer_packet(1, ttl, &[104, 16, 1, 1]);
                assert_eq!(app.rewrite(&mut packet), usize::from(blocked));
                assert_eq!(ttl_of(&packet, 0), ttl.min(30));
            }
        }
    }

    #[test]
    fn leaves_non_cloudflare_and_hintless_responses_untouched() {
        let app = preventive_app();
        for (kind, rdata) in [
            (1, vec![192, 0, 2, 1]),
            (
                28,
                "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets().to_vec(),
            ),
            (65, vec![0, 1, 0, 0, 4, 0, 4, 192, 0, 2, 1]),
            (64, vec![0, 1, 0]),
        ] {
            let mut packet = answer_packet(kind, 300, &rdata);
            let original = packet.clone();
            assert_eq!(app.rewrite(&mut packet), 0);
            assert_eq!(packet, original);
        }
    }

    #[test]
    fn preserves_edns_flags_and_caps_mixed_rrset_consistently() {
        let app = preventive_app();
        let mut packet = answer_packet(1, 300, &[104, 16, 1, 1]);
        packet[7] = 2;
        packet[11] = 1;
        let other = answer_packet(1, 300, &[192, 0, 2, 1]);
        packet.extend(&other[23..]);
        // OPT TTL field contains EDNS extended RCODE/version/flags, not a TTL.
        let opt = [0, 0, 41, 4, 208, 0, 0, 0x80, 0, 0, 0];
        packet.extend(opt);
        app.rewrite(&mut packet);
        assert_eq!(ttl_of(&packet, 0), 30);
        assert_eq!(ttl_of(&packet, 1), 30);
        assert!(packet.ends_with(&opt));
    }

    #[test]
    fn newly_blocked_address_is_rewritten_from_same_upstream_cached_answer() {
        let app = preventive_app();
        let original = answer_packet(1, 3600, &[104, 16, 1, 1]);
        let mut before = original.clone();
        assert_eq!(app.rewrite(&mut before), 0);
        assert_eq!(ttl_of(&before, 0), 30);
        block_v4(&app, [104, 16, 1, 1]);
        let mut after = original;
        assert_eq!(app.rewrite(&mut after), 1);
        assert_eq!(ttl_of(&after, 0), 30);
        assert!(after.ends_with(&[104, 16, 1, 2]));
    }

    #[test]
    fn malformed_packets_do_not_panic_or_change() {
        let app = preventive_app();
        let packet = answer_packet(65, 300, &[0, 1, 0, 0, 4, 0, 4, 104, 16, 1, 1]);
        for length in 0..packet.len() {
            let mut truncated = packet[..length].to_vec();
            let original = truncated.clone();
            assert_eq!(app.rewrite(&mut truncated), 0);
            assert_eq!(truncated, original);
        }
    }

    #[test]
    fn rewrites_a_in_place_and_sets_ttl() {
        let mut packet = vec![
            0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 1, b'a', 3, b'c', b'o', b'm', 0, 0, 1,
            0, 1, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4, 104, 16, 1, 1,
        ];
        let data = Data::new(
            HashSet::from([u32::from(Ipv4Addr::new(104, 16, 1, 1))]),
            HashSet::new(),
            vec![(
                u32::from(Ipv4Addr::new(104, 16, 0, 0)),
                u32::from(Ipv4Addr::new(104, 16, 255, 255)),
            )],
            Vec::new(),
        );
        let app = App {
            data: RwLock::new(Arc::new(data)),
            counters: Counters::default(),
            paths: Paths::from_env(true),
            test_redirects: HashMap::new(),
            temporary_redirects: RwLock::new(Arc::new(HashMap::new())),
            limits: Limits::default(),
        };
        assert_eq!(app.rewrite(&mut packet), 1);
        assert_eq!(&packet[packet.len() - 4..], &[104, 16, 1, 2]);
        assert_eq!(
            &packet[packet.len() - 10..packet.len() - 6],
            &DEFAULT_REWRITE_TTL.to_be_bytes()
        );
    }

    #[test]
    fn rewrites_https_ipv4hint_and_sets_ttl() {
        // HTTPS (type 65) answer for a.com carrying ipv4hint=104.16.1.1.
        // RDATA: priority(0001) target(00) key4(0004) len(0004) hint(104.16.1.1)
        let mut packet = vec![
            0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, // header
            1, b'a', 3, b'c', b'o', b'm', 0, 0, 65, 0, 1, // question a.com HTTPS IN
            0xc0, 0x0c, 0, 65, 0, 1, 0, 0, 1, 0x2c, // answer name/type/class/ttl
            0, 11, // rdlen = 11
            0, 1, 0, 0, 4, 0, 4, 104, 16, 1, 1, // rdata
        ];
        let ttl_at = 29;
        let hint_at = packet.len() - 4;
        let data = Data::new(
            HashSet::from([u32::from(Ipv4Addr::new(104, 16, 1, 1))]),
            HashSet::new(),
            vec![(
                u32::from(Ipv4Addr::new(104, 16, 0, 0)),
                u32::from(Ipv4Addr::new(104, 16, 255, 255)),
            )],
            Vec::new(),
        );
        let app = App {
            data: RwLock::new(Arc::new(data)),
            counters: Counters::default(),
            paths: Paths::from_env(true),
            test_redirects: HashMap::new(),
            temporary_redirects: RwLock::new(Arc::new(HashMap::new())),
            limits: Limits::default(),
        };
        assert_eq!(app.rewrite(&mut packet), 1);
        assert_eq!(&packet[hint_at..hint_at + 4], &[104, 16, 1, 2]);
        assert_eq!(
            &packet[ttl_at..ttl_at + 4],
            &DEFAULT_REWRITE_TTL.to_be_bytes()
        );
    }

    #[test]
    fn test_mode_redirects_only_matching_question() {
        let original = [104, 16, 1, 1];
        let mut packet = vec![
            0x12,
            0x34,
            0x81,
            0x80,
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            1,
            b'a',
            3,
            b'c',
            b'o',
            b'm',
            0,
            0,
            1,
            0,
            1,
            0xc0,
            0x0c,
            0,
            1,
            0,
            1,
            0,
            0,
            1,
            0x2c,
            0,
            4,
            original[0],
            original[1],
            original[2],
            original[3],
        ];
        let mut rules = HashMap::new();
        add_redirect(&mut rules, "a.com=203.0.113.7").unwrap();
        let app = App {
            data: RwLock::new(Arc::new(Data::default())),
            counters: Counters::default(),
            paths: Paths::from_env(true),
            test_redirects: rules,
            temporary_redirects: RwLock::new(Arc::new(HashMap::new())),
            limits: Limits::default(),
        };
        assert_eq!(app.rewrite(&mut packet), 1);
        assert_eq!(&packet[packet.len() - 4..], &[203, 0, 113, 7]);
    }

    fn udp_test_app(limits: Limits) -> Arc<App> {
        Arc::new(App {
            data: RwLock::new(Arc::new(Data::default())),
            counters: Counters::default(),
            paths: Paths::from_env(true),
            test_redirects: HashMap::new(),
            temporary_redirects: RwLock::new(Arc::new(HashMap::new())),
            limits,
        })
    }

    const QUERY: [u8; 17] = [
        0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1,
    ];

    #[tokio::test]
    async fn udp_relays_large_responses_intact() {
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let mut response = QUERY.to_vec();
        response.resize(9000, 0xab);
        let expected = response.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (_, peer) = upstream.recv_from(&mut buf).await.unwrap();
            upstream.send_to(&response, peer).await.unwrap();
        });
        let proxy = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let proxy_addr = proxy.local_addr().unwrap();
        let app = udp_test_app(Limits::default());
        tokio::spawn(serve_udp(app.clone(), proxy, upstream_addr));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&QUERY, proxy_addr).await.unwrap();
        let mut buf = vec![0u8; UDP_LIMIT];
        let len = timeout(Duration::from_secs(2), client.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..len], &expected[..]);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(app.limits.inflight_udp(), 0);
    }

    #[tokio::test]
    async fn udp_drops_queries_beyond_the_inflight_limit() {
        // Upstream that never answers keeps the only slot busy.
        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let proxy = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let proxy_addr = proxy.local_addr().unwrap();
        let app = udp_test_app(Limits::new(1, 1));
        tokio::spawn(serve_udp(
            app.clone(),
            proxy,
            upstream.local_addr().unwrap(),
        ));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for _ in 0..3 {
            client.send_to(&QUERY, proxy_addr).await.unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
        assert_eq!(app.limits.inflight_udp(), 1);
        assert_eq!(app.counters.dropped_udp.load(Relaxed), 2);
    }

    #[test]
    fn clears_ad_flag_only_when_an_address_is_rewritten() {
        let app = preventive_app();
        // answer_packet sets AD (flags 0x81a0).
        let mut untouched = answer_packet(1, 300, &[104, 16, 1, 1]);
        app.rewrite(&mut untouched);
        assert_eq!(untouched[3] & 0x20, 0x20);

        block_v4(&app, [104, 16, 1, 1]);
        let mut rewritten = answer_packet(1, 300, &[104, 16, 1, 1]);
        assert_eq!(app.rewrite(&mut rewritten), 1);
        assert_eq!(rewritten[3] & 0x20, 0);
    }

    #[tokio::test]
    async fn tcp_answers_several_queries_on_one_connection() {
        // Upstream echoes each framed query back, over one connection.
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream.local_addr().unwrap();
        let accepted = Arc::new(AtomicU64::new(0));
        let counter = accepted.clone();
        tokio::spawn(async move {
            loop {
                let (mut conn, _) = upstream.accept().await.unwrap();
                counter.fetch_add(1, Relaxed);
                tokio::spawn(async move {
                    while let Ok(len) = conn.read_u16().await {
                        let mut msg = vec![0; len as usize];
                        conn.read_exact(&mut msg).await.unwrap();
                        conn.write_all(&tcp_frame(&msg)).await.unwrap();
                    }
                });
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        tokio::spawn(serve_tcp(
            udp_test_app(Limits::default()),
            listener,
            upstream_addr,
        ));

        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        for id in 0..3u8 {
            let mut query = QUERY.to_vec();
            query[1] = id;
            client.write_all(&tcp_frame(&query)).await.unwrap();
            let len = client.read_u16().await.unwrap() as usize;
            let mut answer = vec![0; len];
            client.read_exact(&mut answer).await.unwrap();
            assert_eq!(answer, query);
        }
        assert_eq!(accepted.load(Relaxed), 1);
    }

    #[tokio::test]
    async fn unreadable_list_keeps_previous_entries() {
        let dir = std::env::temp_dir().join(format!("evade-proxy-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut paths = Paths::from_env(true);
        paths.blocked_v4 = dir.join("v4");
        paths.blocked_v6 = dir.join("v6");
        paths.cf_v4 = dir.join("cf4");
        paths.cf_v6 = dir.join("cf6");
        std::fs::write(&paths.blocked_v4, "104.16.1.1\n").unwrap();
        std::fs::write(&paths.blocked_v6, "").unwrap();
        std::fs::write(&paths.cf_v4, "104.16.0.0/12\n").unwrap();
        std::fs::write(&paths.cf_v6, "").unwrap();
        let first = Data::load(&paths, None).await;
        assert_eq!(first.evasive_v4(0x6810_0101), Some(0x6810_0102));

        std::fs::remove_file(&paths.blocked_v4).unwrap();
        std::fs::remove_file(&paths.cf_v4).unwrap();
        let second = Data::load(&paths, Some(&first)).await;
        assert_eq!(second.evasive_v4(0x6810_0101), Some(0x6810_0102));

        std::fs::write(&paths.blocked_v4, "").unwrap();
        let third = Data::load(&paths, Some(&second)).await;
        assert!(third.blocked_v4.is_empty()); // an empty file is a real update
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn redirect_app(rule: &str) -> App {
        let mut rules = HashMap::new();
        add_redirect(&mut rules, rule).unwrap();
        App {
            data: RwLock::new(Arc::new(Data::default())),
            counters: Counters::default(),
            paths: Paths::from_env(true),
            test_redirects: rules,
            temporary_redirects: RwLock::new(Arc::new(HashMap::new())),
            limits: Limits::default(),
        }
    }

    // answer_packet plus an EDNS OPT record with the DO bit.
    fn with_opt(mut packet: Vec<u8>) -> Vec<u8> {
        packet[11] = 1;
        packet.extend([0, 0, 41, 4, 208, 0, 0, 0x80, 0, 0, 0]);
        packet
    }

    #[test]
    fn v4_only_redirect_empties_aaaa_and_https_but_keeps_opt() {
        let app = redirect_app("a.com=203.0.113.7");
        let v6 = "2606:4700::1".parse::<Ipv6Addr>().unwrap().octets();
        let https = [0, 1, 0, 0, 6, 0, 16]
            .iter()
            .copied()
            .chain(v6)
            .collect::<Vec<_>>();
        for (kind, rdata) in [(28u16, v6.to_vec()), (65, https)] {
            let original = with_opt(answer_packet(kind, 300, &rdata));
            let mut packet = original.clone();
            assert_eq!(app.process(&mut packet), 1);
            let question_end = skip_name(&packet, 12).unwrap() + 4;
            assert_eq!(&packet[..2], &original[..2]); // same ID
            assert_eq!(be16(&packet, 6), Some(0)); // no answers
            assert_eq!(be16(&packet, 10), Some(1)); // OPT kept
            assert_eq!(packet[3] & 0x20, 0); // AD cleared
            assert_eq!(
                &packet[question_end..],
                &[0, 0, 41, 4, 208, 0, 0, 0x80, 0, 0, 0]
            );
        }
    }

    #[test]
    fn v4_only_redirect_still_rewrites_a() {
        let app = redirect_app("a.com=203.0.113.7");
        let mut packet = with_opt(answer_packet(1, 300, &[104, 16, 1, 1]));
        assert_eq!(app.process(&mut packet), 1);
        assert_eq!(be16(&packet, 6), Some(1));
        let rr = resource_records(&packet).unwrap()[0];
        assert_eq!(&packet[rr.rdata..rr.rdata + 4], &[203, 0, 113, 7]);
    }

    #[test]
    fn aaaa_is_kept_without_redirect_or_with_an_ipv6_redirect() {
        let v6 = "2606:4700::1".parse::<Ipv6Addr>().unwrap().octets();
        let plain = App {
            test_redirects: HashMap::new(),
            ..redirect_app("a.com=203.0.113.7")
        };
        let mut packet = with_opt(answer_packet(28, 300, &v6));
        plain.process(&mut packet);
        assert_eq!(be16(&packet, 6), Some(1));

        let dual = redirect_app("a.com=203.0.113.7");
        let mut rules = dual.test_redirects.clone();
        add_redirect(&mut rules, "a.com=2001:db8::7").unwrap();
        let dual = App {
            test_redirects: rules,
            ..dual
        };
        let mut packet = with_opt(answer_packet(28, 300, &v6));
        assert_eq!(dual.process(&mut packet), 1);
        assert_eq!(be16(&packet, 6), Some(1));
        let rr = resource_records(&packet).unwrap()[0];
        assert_eq!(
            &packet[rr.rdata..rr.rdata + 16],
            &"2001:db8::7".parse::<Ipv6Addr>().unwrap().octets()
        );
    }

    #[test]
    fn parses_and_merges_prefixes() {
        assert_eq!(
            parse_v4_prefix("104.16.1.2/24"),
            Some((0x6810_0100, 0x6810_01ff))
        );
        assert_eq!(
            merge_v4([(1, 3), (4, 7), (10, 11)].into_iter()),
            vec![(1, 7), (10, 11)]
        );
    }

    #[test]
    fn temporary_redirects_require_a_future_expiry() {
        let rules = parse_temporary_redirects(
            "expired.example=192.0.2.1 999\nactive.example=192.0.2.2 1001\n",
            1000.0,
        );
        assert!(!rules.contains_key("expired.example"));
        assert_eq!(
            rules["active.example"].v4,
            Some(u32::from(Ipv4Addr::new(192, 0, 2, 2)))
        );
        assert_eq!(rules["active.example"].expires_at, Some(1001.0));
    }
}
