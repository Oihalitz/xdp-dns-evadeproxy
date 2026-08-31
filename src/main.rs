use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, Ipv6Addr},
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
    time::timeout,
};

const LISTEN_HOST: &str = "127.0.0.1";
const UPSTREAM_HOST: &str = "127.0.0.1";
const PRODUCTION_PORT_PAIRS: &[(u16, u16)] = &[(5335, 5336), (5337, 5338)];
const TEST_PORT_PAIRS: &[(u16, u16)] = &[(15335, 5336), (15337, 5338)];
const PRODUCTION_METRICS_PORT: u16 = 5339;
const TEST_METRICS_PORT: u16 = 15339;
const UDP_LIMIT: usize = 65_535;

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

#[derive(Clone, Debug)]
struct Paths {
    blocked_v4: PathBuf,
    blocked_v6: PathBuf,
    cf_v4: PathBuf,
    cf_v6: PathBuf,
    stats: PathBuf,
    redirects: PathBuf,
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
                "/etc/unbound/cloudflare_prefixes_v4.txt",
            ),
            cf_v6: value(
                "EVADE_CF_IPV6_FILE",
                "/etc/unbound/cloudflare_prefixes_v6.txt",
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

    async fn load(paths: &Paths, verbose: bool) -> Self {
        let (v4, v6, cf4, cf6) = tokio::join!(
            read_lines(&paths.blocked_v4),
            read_lines(&paths.blocked_v6),
            read_lines(&paths.cf_v4),
            read_lines(&paths.cf_v6)
        );
        let blocked_v4 = v4
            .iter()
            .filter_map(|s| Ipv4Addr::from_str(s).ok())
            .map(u32::from)
            .collect();
        let blocked_v6 = v6
            .iter()
            .filter_map(|s| Ipv6Addr::from_str(s).ok())
            .map(u128::from)
            .collect();
        let cf_v4 = merge_v4(cf4.iter().filter_map(|s| parse_v4_prefix(s)));
        let cf_v6 = merge_v6(cf6.iter().filter_map(|s| parse_v6_prefix(s)));
        let data = Self::new(blocked_v4, blocked_v6, cf_v4, cf_v6);
        if verbose {
            eprintln!(
                "loaded {} blocked IPv4, {} blocked IPv6, {} Cloudflare IPv4 intervals, {} IPv6 intervals",
                data.blocked_v4.len(), data.blocked_v6.len(), data.cf_v4.len(), data.cf_v6.len()
            );
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

struct App {
    data: RwLock<Arc<Data>>,
    counters: Counters,
    paths: Paths,
    test_redirects: HashMap<String, TestRedirect>,
    temporary_redirects: RwLock<Arc<HashMap<String, TestRedirect>>>,
}

impl App {
    async fn new(paths: Paths, test_redirects: HashMap<String, TestRedirect>) -> Arc<Self> {
        let data = Data::load(&paths, true).await;
        let counters = Counters::load(&paths.stats).await;
        let temporary_redirects = load_temporary_redirects(&paths.redirects).await;
        Arc::new(Self {
            data: RwLock::new(Arc::new(data)),
            counters,
            paths,
            test_redirects,
            temporary_redirects: RwLock::new(Arc::new(temporary_redirects)),
        })
    }

    fn rewrite(&self, packet: &mut [u8]) -> usize {
        self.counters.total_queries.fetch_add(1, Relaxed);
        let data = self.data.read().expect("data lock poisoned").clone();
        let temporary_redirects = self
            .temporary_redirects
            .read()
            .expect("redirect lock poisoned")
            .clone();
        // Decoding the question name allocates (labels, lowercasing, join). Only pay
        // for it when some redirect rule actually exists — in production neither map
        // is populated most of the time, so this is skipped on the common path.
        let has_redirects = !self.test_redirects.is_empty() || !temporary_redirects.is_empty();
        let test_redirect = if has_redirects {
            question_name(packet)
                .and_then(|domain| {
                    self.test_redirects
                        .get(&domain)
                        .or_else(|| temporary_redirects.get(&domain))
                })
                .filter(|redirect| redirect.expires_at.is_none_or(|expires| expires > epoch()))
        } else {
            None
        };
        if test_redirect.is_none() && data.blocked_v4.is_empty() && data.blocked_v6.is_empty() {
            return 0;
        }
        let records = match resource_records(packet) {
            Some(records) => records,
            None => return 0,
        };
        let mut changes: Vec<(usize, Vec<u8>)> = Vec::new();
        for rr in &records {
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
                    changes.extend(svcb_hint_changes(packet, rr, data.as_ref(), redirect));
                }
                _ => {}
            }
        }
        if changes.is_empty() {
            return 0;
        }
        for rr in records {
            packet[rr.ttl..rr.ttl + 4].fill(0);
        }
        for (offset, bytes) in &changes {
            packet[*offset..*offset + bytes.len()].copy_from_slice(bytes);
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
    eprintln!("DNS UDP {LISTEN_HOST}:{listen} -> {UPSTREAM_HOST}:{upstream}");
    loop {
        let mut buffer = vec![0u8; UDP_LIMIT];
        let (len, peer) = socket.recv_from(&mut buffer).await?;
        buffer.truncate(len);
        let app = app.clone();
        let socket = socket.clone();
        tokio::spawn(async move {
            if let Ok(Ok(up)) =
                timeout(Duration::from_secs(3), UdpSocket::bind((LISTEN_HOST, 0))).await
            {
                if up.connect((UPSTREAM_HOST, upstream)).await.is_ok()
                    && up.send(&buffer).await.is_ok()
                {
                    buffer.resize(UDP_LIMIT, 0);
                    if let Ok(Ok(len)) = timeout(Duration::from_secs(3), up.recv(&mut buffer)).await
                    {
                        app.rewrite(&mut buffer[..len]);
                        let _ = socket.send_to(&buffer[..len], peer).await;
                    }
                }
            }
        });
    }
}

async fn tcp_server(app: Arc<App>, listen: u16, upstream: u16) -> Result<()> {
    let listener = TcpListener::bind((LISTEN_HOST, listen)).await?;
    eprintln!("DNS TCP {LISTEN_HOST}:{listen} -> {UPSTREAM_HOST}:{upstream}");
    loop {
        let (client, _) = listener.accept().await?;
        let app = app.clone();
        tokio::spawn(async move {
            let _ = handle_tcp(app, client, upstream).await;
        });
    }
}

async fn handle_tcp(app: Arc<App>, mut client: TcpStream, upstream_port: u16) -> Result<()> {
    let len = timeout(Duration::from_secs(3), client.read_u16()).await?? as usize;
    let mut query = vec![0; len];
    timeout(Duration::from_secs(3), client.read_exact(&mut query)).await??;
    let mut upstream = timeout(
        Duration::from_secs(3),
        TcpStream::connect((UPSTREAM_HOST, upstream_port)),
    )
    .await??;
    upstream.write_u16(len as u16).await?;
    upstream.write_all(&query).await?;
    let response_len = timeout(Duration::from_secs(3), upstream.read_u16()).await?? as usize;
    let mut response = vec![0; response_len];
    timeout(Duration::from_secs(3), upstream.read_exact(&mut response)).await??;
    app.rewrite(&mut response);
    client.write_u16(response.len() as u16).await?;
    client.write_all(&response).await?;
    Ok(())
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
        ("text/plain; version=0.0.4", format!(
            "# HELP xdp_evade_queries_total Total DNS queries rewritten for block evasion\n# TYPE xdp_evade_queries_total counter\nxdp_evade_queries_total {}\n# HELP xdp_evade_records_total Total DNS records replaced for block evasion\n# TYPE xdp_evade_records_total counter\nxdp_evade_records_total {}\n# HELP xdp_evade_queries_processed Total queries processed by evasion proxy\n# TYPE xdp_evade_queries_processed counter\nxdp_evade_queries_processed {}\n",
            stats.evaded_queries_total, stats.evaded_records_total, stats.total_queries_processed))
    } else {
        ("application/json", serde_json::to_string_pretty(&stats)?)
    };
    let response = format!("HTTP/1.1 200 OK\r\nContent-Type: {kind}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    reader.get_mut().write_all(response.as_bytes()).await?;
    Ok(())
}

async fn maintenance(app: Arc<App>) {
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    let mut ticks = 0u8;
    loop {
        ticker.tick().await;
        let redirects = load_temporary_redirects(&app.paths.redirects).await;
        {
            let mut current = app
                .temporary_redirects
                .write()
                .expect("redirect lock poisoned");
            if current.as_ref() != &redirects {
                eprintln!("loaded {} active temporary redirect(s)", redirects.len());
                *current = Arc::new(redirects);
            }
        }

        ticks = ticks.wrapping_add(1);
        if ticks % 5 == 0 {
            let new_data = Data::load(&app.paths, false).await;
            *app.data.write().expect("data lock poisoned") = Arc::new(new_data);
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

async fn read_lines(path: &Path) -> Vec<String> {
    tokio::fs::read_to_string(path)
        .await
        .unwrap_or_default()
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .map(str::to_owned)
        .collect()
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
    servers.spawn(metrics_server(app, metrics_port));

    tokio::select! {
        signal = tokio::signal::ctrl_c() => signal?,
        result = servers.join_next() => match result {
            Some(Ok(Err(error))) => return Err(error),
            Some(Err(error)) => return Err(error.into()),
            Some(Ok(Ok(()))) => bail!("a server task stopped unexpectedly"),
            None => bail!("all server tasks stopped unexpectedly"),
        }
    }
    maintenance_task.abort();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_a_in_place_and_zeros_ttl() {
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
        };
        assert_eq!(app.rewrite(&mut packet), 1);
        assert_eq!(&packet[packet.len() - 4..], &[104, 16, 1, 2]);
        assert_eq!(&packet[packet.len() - 10..packet.len() - 6], &[0, 0, 0, 0]);
    }

    #[test]
    fn rewrites_https_ipv4hint_and_zeros_ttl() {
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
        };
        assert_eq!(app.rewrite(&mut packet), 1);
        assert_eq!(&packet[hint_at..hint_at + 4], &[104, 16, 1, 2]);
        assert_eq!(&packet[ttl_at..ttl_at + 4], &[0, 0, 0, 0]);
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
        };
        assert_eq!(app.rewrite(&mut packet), 1);
        assert_eq!(&packet[packet.len() - 4..], &[203, 0, 113, 7]);
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
