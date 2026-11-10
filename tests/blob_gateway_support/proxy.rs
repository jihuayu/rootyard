//! Task-owned, bounded, loopback-only HTTP proxy for the issue-126
//! receive-pack protocol cases.
//!
//! [`Proxy`] sits between the real stock Git clients and one already running
//! `serve-blob` service. It records every exchange it sees (method, path,
//! status, the advertisement body and the digest of the exact receive-pack
//! request body that reached the service) and applies only explicitly armed
//! rules to receive-pack POSTs:
//!
//! - [`Proxy::hold_connection`] holds the responses of the next `count` POSTs,
//!   so two stock Git clients compete against one advertised old OID and the
//!   service sees both complete requests;
//! - [`Proxy::resolve_held`] forwards every held request concurrently, only
//!   after every held body is complete, and answers each client with **its own**
//!   service response;
//! - [`Proxy::drop_operation`] forwards one POST with the caller's
//!   `X-Rootyard-Operation`, consumes the complete service response (after the
//!   service-side operation is durably terminal when a [`Poll`] is attached) and
//!   then closes the client connection without writing one byte.
//!
//! The proxy replaces only the client transport: every client reads exactly the
//! service response to its own bytes.
//!
//! Bounds: a barrier admits exactly `count` requests and every held response is
//! bounded by [`Limits::hold`]; bodies are read under [`Limits::max_body`],
//! responses under [`Limits::max_response`]; at most [`Limits::max_connections`]
//! client connections are served at once and every read/write on them is bounded
//! by [`Limits::idle`]. Only loopback peers are accepted. No dependency beyond
//! the crates the library already uses is added.
use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex as StdMutex},
    time::Duration,
};

use anyhow::{Result, anyhow, bail, ensure};
use sha2::{Digest, Sha256};
use tokio::{
    io::BufReader,
    net::{TcpListener, TcpStream},
    sync::{Mutex, Semaphore, mpsc, oneshot},
    task::JoinSet,
    time::{Instant, sleep, timeout},
};

use super::{
    actor::Actor,
    db::{Db, pool_for},
    git::clone_url,
    wire::{self, Bounds},
};
#[cfg(test)]
#[path = "proxy_reply.rs"]
mod proxy_reply;

/// Bounds of one proxy: bodies, responses, connections, socket I/O and held
/// receive-pack answers.
#[derive(Clone)]
pub struct Limits {
    pub max_body: usize,
    pub max_response: usize,
    pub max_connections: usize,
    pub idle: Duration,
    pub hold: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_body: 64 * 1024 * 1024,
            max_response: 64 * 1024 * 1024,
            max_connections: 64,
            idle: Duration::from_secs(120),
            hold: Duration::from_secs(240),
        }
    }
}

pub fn sha256(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

/// Loopback-only peers and backends; nothing else is ever accepted.
pub(super) fn loopback(address: SocketAddr) -> bool {
    match address.ip() {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// A create exchange whose answer named its operation.
#[derive(Debug, Clone)]
pub struct CreatedOperation {
    pub operation: uuid::Uuid,
}

/// One exchange the proxy saw (bounded metadata only).
#[derive(Debug, Clone)]
pub struct Record {
    pub method: String,
    pub path: String,
    pub status: Option<u16>,
    /// Digest of the request body that reached the service.
    pub request_sha256: String,
    pub request_bytes: usize,
    /// Advertisement body after the service pkt-line prefix, for
    /// `info/refs?service=git-receive-pack` only.
    pub advertisement: Option<Vec<u8>>,
    /// `X-Rootyard-Operation` the service answered on the create API. `None` on
    /// every other exchange.
    pub operation: Option<CreatedOperation>,
    pub truncated: bool,
}

/// Raw backend traffic of one armed receive-pack POST. It stays in the proxy for
/// the service-side ruling and is never replayed to the Git client.
pub struct Captured {
    pub request_sha256: String,
    pub status: Option<u16>,
    pub response: Vec<u8>,
}

#[derive(Clone)]
struct Reply {
    status: u16,
    reason: &'static str,
    /// The backend's end-to-end response headers, kept verbatim so a stock Git
    /// client sees the real `WWW-Authenticate` challenge, `Content-Type` and
    /// `X-Rootyard-Operation`. Empty when the answer is not a backend response.
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// One held request whose answer is forwarded after the barrier opened. It is
/// created per connection and shared with the barrier.
struct Deferred {
    backend: SocketAddr,
    max_body: usize,
    max_response: usize,
    idle: Duration,
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    /// The body that will reach the service, byte for byte as the client sent it.
    body: Vec<u8>,
    joint: Option<Arc<tokio::sync::Mutex<Option<Outcome>>>>,
}

type DeferredRef = Arc<Deferred>;

#[derive(Clone)]
enum Rule {
    /// Hold this request (real body) until the barrier opens; forward it, then
    /// answer with its own response.
    Hold { outcome: Arc<tokio::sync::Mutex<Option<Outcome>>>, captured: Option<mpsc::UnboundedSender<Captured>> },
    /// Consume the service response, then drop the client connection.
    Drop { poll: Option<Poll>, captured: mpsc::UnboundedSender<Captured> },
}

/// The complete answer of one forwarded request, or why it was lost.
type Outcome = std::result::Result<Reply, String>;

struct Hold {
    count: usize,
    /// Every held request, in arrival order; each keeps its own reply channel.
    arrived: Vec<DeferredRef>,
}

/// Armed rules: connection-wide (`hold_connection`) and per operation.
#[derive(Default)]
struct Rules {
    connection: Vec<Rule>,
    operation: Vec<(String, Rule)>,
}

struct State {
    records: Vec<Record>,
    rules: Rules,
    hold: Option<Hold>,
}

struct Shared {
    backend: SocketAddr,
    limits: Limits,
    state: Mutex<State>,
    failure: StdMutex<Option<String>>,
}

impl Shared {
    fn fail(&self, message: impl Into<String>) {
        let mut slot = self.failure.lock().expect("proxy failure lock");
        if slot.is_none() {
            *slot = Some(message.into());
        }
    }

    fn failure(&self) -> Option<String> {
        self.failure.lock().expect("proxy failure lock").clone()
    }

    fn bounds(&self) -> Bounds<'_> {
        Bounds { max_body: self.limits.max_body, max_response: self.limits.max_response, idle: &self.limits.idle }
    }

    async fn exchange(
        &self,
        method: &str,
        target: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<wire::BackendTraffic> {
        wire::exchange(self.backend, &self.bounds(), method, target, headers, body).await
    }
}

/// Service-side terminal poll: a `Drop` rule does not cut the response before
/// the service-side operation reached a durable terminal.
#[derive(Clone)]
pub struct Poll {
    database_url: String,
    schema: String,
    owner: String,
    name: String,
    operation: uuid::Uuid,
}

impl Poll {
    pub fn new(db: &Db, owner: &Actor, name: &str, operation: uuid::Uuid) -> Self {
        Self {
            database_url: db.database_url().to_owned(),
            schema: db.schema().to_owned(),
            owner: owner.username.clone(),
            name: name.to_owned(),
            operation,
        }
    }

    pub async fn state(&self) -> Result<Option<String>> {
        let pool = pool_for(&self.database_url, &self.schema, 2)?;
        let row = pool
            .get()
            .await?
            .query_opt(
                "SELECT o.state FROM ref_store_operations o
                   JOIN repositories r ON r.id=o.repository_id
                   JOIN namespaces ns ON ns.id=r.owner_id
                  WHERE ns.slug=$1 AND r.name=$2 AND o.operation_id=$3",
                &[&self.owner, &self.name, &self.operation],
            )
            .await?;
        Ok(row.map(|row| row.get(0)))
    }

    pub async fn wait_terminal(&self, bound: Instant) -> Result<String> {
        loop {
            if let Some(state) = self.state().await?
                && matches!(state.as_str(), "committed" | "rejected" | "cancelled")
            {
                return Ok(state);
            }
            ensure!(Instant::now() < bound, "service-side operation did not reach a durable terminal");
            sleep(Duration::from_millis(100)).await;
        }
    }
}

/// One loopback-only HTTP proxy in front of the real service.
pub struct Proxy {
    address: SocketAddr,
    shared: Arc<Shared>,
    shutdown: oneshot::Sender<()>,
    acceptor: tokio::task::JoinHandle<()>,
}

impl Proxy {
    pub async fn start(backend: SocketAddr, limits: Limits) -> Result<Self> {
        ensure!(loopback(backend), "proxy backend must be a loopback service");
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let address = listener.local_addr()?;
        ensure!(loopback(address), "proxy listener must be loopback");
        ensure!(limits.max_connections >= 2, "the proxy needs at least two client connections");
        let shared = Arc::new(Shared {
            backend,
            limits,
            state: Mutex::new(State { records: Vec::new(), rules: Rules::default(), hold: None }),
            failure: StdMutex::new(None),
        });
        let (shutdown, stopped) = oneshot::channel::<()>();
        let acceptor_shared = shared.clone();
        let acceptor = tokio::spawn(async move {
            let permits = Arc::new(Semaphore::new(acceptor_shared.limits.max_connections));
            let mut children = JoinSet::new();
            tokio::pin!(stopped);
            loop {
                tokio::select! {
                    _ = &mut stopped => break,
                    accepted = listener.accept() => {
                        let Ok((stream, peer)) = accepted else { break };
                        if !loopback(peer) {
                            acceptor_shared.fail("proxy accepted a non-loopback peer");
                            continue;
                        }
                        let Ok(permit) = permits.clone().try_acquire_owned() else {
                            acceptor_shared.fail("proxy connection bound exhausted");
                            continue;
                        };
                        let shared = acceptor_shared.clone();
                        children.spawn(async move {
                            let _permit = permit;
                            if let Err(error) = serve(stream, shared.clone()).await {
                                shared.fail(format!("proxy connection ended: {error:#}"));
                            }
                        });
                    }
                }
            }
            children.abort_all();
            while children.join_next().await.is_some() {}
        });
        Ok(Self { address, shared, shutdown, acceptor })
    }

    /// The clone URL of one repository through this proxy, with the owner's real
    /// credentials in the URL exactly as a stock client puts them.
    pub fn url(&self, owner: &Actor, name: &str) -> String {
        clone_url(self.address, &owner.username, name, &owner.username, &owner.token)
    }

    /// Arm the barrier for the next `count` receive-pack POSTs (the two stock
    /// Git pushes). Their service responses are not returned to Git before
    /// [`Proxy::resolve_held`] forwarded all of them concurrently.
    pub async fn hold_connection(&self, count: usize) -> Result<()> {
        ensure!(count >= 1, "a hold barrier needs at least one request");
        let mut state = self.shared.state.lock().await;
        ensure!(state.hold.is_none(), "a hold barrier is already armed");
        ensure!(state.rules.connection.is_empty(), "a rewrite rule is already armed");
        state.rules.connection = (0..count)
            .map(|_| Rule::Hold { outcome: Arc::new(tokio::sync::Mutex::new(None)), captured: None })
            .collect();
        state.hold = Some(Hold { count, arrived: Vec::new() });
        Ok(())
    }

    /// Forward the next POST carrying `operation` and then close its client
    /// connection without writing one byte. The complete service response (after
    /// the `poll` reached a durable terminal, when attached) is sent back here
    /// for an explicit service-side ruling; it is never replayed to Git.
    pub fn drop_operation(&self, operation: &str, poll: Option<Poll>) -> Result<mpsc::UnboundedReceiver<Captured>> {
        let mut state = self.shared.state.try_lock().map_err(|_| anyhow!("proxy state is busy; arm before pushing"))?;
        ensure!(
            !state.rules.operation.iter().any(|(armed, _)| armed == operation),
            "an operation drop rule is already armed"
        );
        let (captured, received) = mpsc::unbounded_channel();
        state.rules.operation.push((operation.to_owned(), Rule::Drop { poll, captured }));
        Ok(received)
    }

    /// Wait until `count` requests sit in the armed barrier.
    pub async fn await_held(&self, count: usize) -> Result<()> {
        let bound = Instant::now() + Duration::from_secs(120);
        loop {
            if let Some(failure) = self.shared.failure() {
                bail!("proxy failed: {failure}");
            }
            let arrived = self.shared.state.lock().await.hold.as_ref().map(|hold| hold.arrived.len()).unwrap_or(0);
            if arrived >= count {
                return Ok(());
            }
            ensure!(Instant::now() < bound, "receive-pack requests did not reach the proxy");
            sleep(Duration::from_millis(50)).await;
        }
    }

    /// Forward every held request concurrently and answer each client with its
    /// own service response, unchanged by the proxy.
    pub async fn resolve_held(&self) -> Result<()> {
        resolve_held(&self.shared).await
    }

    pub async fn records(&self) -> Vec<Record> {
        std::mem::take(&mut self.shared.state.lock().await.records)
    }

    pub fn failure(&self) -> Option<String> {
        self.shared.failure()
    }

    pub async fn stop(self) -> Result<()> {
        let _ = self.shutdown.send(());
        let _ = timeout(Duration::from_secs(10), self.acceptor).await;
        Ok(())
    }
}

/// Open the armed barrier: forward every held request concurrently.
async fn resolve_held(shared: &Shared) -> Result<()> {
    let arrived = {
        let mut state = shared.state.lock().await;
        let hold = state.hold.take().ok_or_else(|| anyhow!("no hold barrier is armed"))?;
        ensure!(
            hold.arrived.len() == hold.count,
            "the barrier is not full: {} of {} requests arrived",
            hold.arrived.len(),
            hold.count
        );
        hold.arrived
    };
    let mut forwards = Vec::with_capacity(arrived.len());
    for request in arrived {
        let outcome = request.joint.clone();
        forwards.push(tokio::spawn(async move {
            let reply = forward(&request).await;
            if let Some(outcome) = outcome {
                *outcome.lock().await = Some(reply);
            }
        }));
    }
    for forward in forwards {
        forward.await.map_err(|error| anyhow!("a held forward task failed: {error}"))?;
    }
    Ok(())
}

async fn take_operation_rule(shared: &Shared, operation: &str) -> Option<Rule> {
    let mut state = shared.state.lock().await;
    let index = state.rules.operation.iter().position(|(armed, _)| armed == operation)?;
    Some(state.rules.operation.remove(index).1)
}

fn is_receive_pack_post(path: &str, method: &str) -> bool {
    method == "POST" && path.starts_with("/git/") && path.ends_with("/git-receive-pack")
}

fn operation_of(target: &str, headers: &[(String, String)]) -> Option<String> {
    if let Some(value) = wire::header(headers, "x-rootyard-operation") {
        return Some(value.to_owned());
    }
    let query = target.split_once('?')?.1;
    query.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == "operation").then(|| value.to_owned())
    })
}

async fn serve(stream: TcpStream, shared: Arc<Shared>) -> Result<()> {
    let _ = stream.set_nodelay(true);
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    loop {
        let Some(head) = wire::read_head(&mut reader, shared.limits.idle).await? else { return Ok(()) };
        let (method, target, headers) = wire::parse_head(&head)?;
        let body = wire::read_body(&mut reader, &headers, &shared.bounds()).await?;
        let path = target.split('?').next().unwrap_or(&target).to_owned();
        let mut record = Record {
            method: method.clone(),
            path: path.clone(),
            status: None,
            request_sha256: sha256(&body),
            request_bytes: body.len(),
            advertisement: None,
            operation: None,
            truncated: false,
        };
        let armed = match operation_of(&target, &headers) {
            Some(operation) => take_operation_rule(&shared, &operation).await,
            None => None,
        };
        let rule = match armed {
            Some(rule) => Some(rule),
            None if is_receive_pack_post(&path, &method) => take_connection_rule(&shared).await,
            None => None,
        };
        let reply = match rule {
            Some(Rule::Drop { poll, captured }) => {
                if let Some(poll) = poll {
                    poll.wait_terminal(Instant::now() + shared.limits.hold).await?;
                }
                let traffic = shared.exchange(&method, &target, &headers, &body).await?;
                record.status = Some(traffic.status);
                record.truncated = traffic.truncated;
                shared.state.lock().await.records.push(record);
                let _ = captured.send(Captured {
                    request_sha256: sha256(&body),
                    status: Some(traffic.status),
                    response: traffic.body,
                });
                // The Git client must observe a transport failure, not a response.
                return Ok(());
            }
            Some(Rule::Hold { outcome, captured }) => {
                let deferred = Arc::new(Deferred {
                    backend: shared.backend,
                    max_body: shared.limits.max_body,
                    max_response: shared.limits.max_response,
                    idle: shared.limits.idle,
                    method,
                    target,
                    headers: headers.clone(),
                    body,
                    joint: Some(outcome),
                });
                enroll(&shared, deferred.clone()).await?;
                let reply = await_held_reply(&shared, &deferred).await?;
                if let Some(captured) = captured {
                    let _ = captured.send(Captured {
                        request_sha256: sha256(&deferred.body),
                        status: Some(reply.status),
                        response: reply.body.clone(),
                    });
                }
                reply
            }
            None => {
                let traffic = shared.exchange(&method, &target, &headers, &body).await?;
                record.status = Some(traffic.status);
                record.truncated = traffic.truncated;
                if target.contains("/info/refs?") && target.contains("service=git-receive-pack") {
                    record.advertisement = advertisement_body(&traffic.body);
                }
                if path == "/api/repos" && method == "POST" {
                    record.operation = wire::header(&traffic.headers, "x-rootyard-operation")
                        .and_then(|value| value.parse::<uuid::Uuid>().ok())
                        .map(|operation| CreatedOperation { operation });
                }
                shared.state.lock().await.records.push(record);
                Reply { status: traffic.status, reason: "OK", headers: traffic.headers, body: traffic.body }
            }
        };
        let closed = wire::connection_closed(&headers);
        wire::write_reply(&mut write, shared.limits.idle, reply.status, reply.reason, &reply.headers, &reply.body)
            .await?;
        if closed {
            return Ok(());
        }
    }
}

async fn take_connection_rule(shared: &Shared) -> Option<Rule> {
    let mut state = shared.state.lock().await;
    if state.rules.connection.is_empty() { None } else { Some(state.rules.connection.remove(0)) }
}

/// Join the armed barrier (first request creates it).
async fn enroll(shared: &Shared, request: DeferredRef) -> Result<()> {
    let mut state = shared.state.lock().await;
    let count = match state.hold.as_ref() {
        Some(hold) => {
            ensure!(hold.arrived.len() < hold.count, "hold barrier overflow");
            hold.count
        }
        None => 1,
    };
    if state.hold.is_none() {
        state.hold = Some(Hold { count, arrived: Vec::new() });
    }
    state.hold.as_mut().expect("hold just created").arrived.push(request);
    Ok(())
}

/// Wait for the reply of one held request. Its forward runs only after
/// [`Proxy::resolve_held`] opened the barrier.
async fn await_held_reply(shared: &Shared, request: &DeferredRef) -> Result<Reply> {
    let bound = Instant::now() + shared.limits.hold;
    let joint = request.joint.clone().ok_or_else(|| anyhow!("a held request has no reply channel"))?;
    loop {
        let replied = match joint.lock().await.as_ref() {
            Some(Ok(reply)) => return Ok(reply.clone()),
            Some(Err(message)) => Some(message.clone()),
            None => None,
        };
        if let Some(message) = replied {
            return Err(anyhow::Error::msg(message));
        }
        ensure!(Instant::now() < bound, "held receive-pack response exceeded the proxy hold bound");
        sleep(Duration::from_millis(10)).await;
    }
}

/// Forward one held request exactly once and record its own complete answer.
async fn forward(request: &DeferredRef) -> Outcome {
    let Ok(traffic) = wire::exchange(
        request.backend,
        &Bounds { max_body: request.max_body, max_response: request.max_response, idle: &request.idle },
        &request.method,
        &request.target,
        &request.headers,
        &request.body,
    )
    .await
    else {
        return Err("forward failed".to_owned());
    };
    Ok(Reply { status: traffic.status, reason: "OK", headers: traffic.headers, body: traffic.body })
}

/// Advertisement body after the `# service=git-receive-pack` pkt-line prefix.
fn advertisement_body(body: &[u8]) -> Option<Vec<u8>> {
    let mut position = 0usize;
    while position + 4 <= body.len() {
        let text = std::str::from_utf8(&body[position..position + 4]).ok()?;
        let length = usize::from_str_radix(text, 16).ok()?;
        position += 4;
        if length == 0 {
            return Some(body[position..].to_vec());
        }
        if length < 4 || position + length - 4 > body.len() {
            return None;
        }
        position += length - 4;
    }
    None
}

/// Decode the ref pkt-lines of a receive-pack advertisement into `(oid, ref)`
/// pairs and the capability string of the first line.
pub fn parse_advertisement(body: &[u8]) -> Result<(Vec<(String, String)>, String)> {
    let (lines, _) = wire::pkt_lines_until_flush(body)?;
    let mut refs = Vec::new();
    let mut capabilities = String::new();
    for payload in lines {
        let payload = std::str::from_utf8(&payload)
            .map_err(|_| anyhow!("advertisement payload is not UTF-8"))?
            .trim_end_matches('\n');
        #[allow(unused_assignments)]
        let (line, caps) = match payload.split_once('\0') {
            Some((line, caps)) => (line, Some(caps)),
            None => (payload, None),
        };
        let mut fields = line.split(' ');
        let (Some(oid), Some(name), None) = (fields.next(), fields.next(), fields.next()) else {
            bail!("advertisement ref line is malformed");
        };
        if let Some(caps) = caps {
            capabilities = caps.to_owned();
        } else if !refs.is_empty() && !line.starts_with("shallow ") && !line.is_empty() && line.len() == 45 {
            // A v1 advertisement may continue with further ref lines; a peeled
            // tag line (`<oid> <ref>^{}`) names no new ref.
        }
        if name.starts_with("refs/") {
            refs.push((oid.to_owned(), name.to_owned()));
        }
    }
    Ok((refs, capabilities))
}
