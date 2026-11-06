//! Kafka is an advisory wake transport, not a second durable task authority.
use crate::dispatch::WakeTransport;
use anyhow::{Context, Result, ensure};
use rdkafka::{
    ClientConfig, ClientContext, Message,
    config::RDKafkaLogLevel,
    consumer::{BaseConsumer, Consumer, ConsumerContext, Rebalance},
    error::KafkaError,
    message::Headers,
    producer::{FutureProducer, FutureRecord},
    util::Timeout,
};
use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Notify, OnceCell, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

type Task<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
fn valid_name(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
#[derive(Clone)]
struct Options {
    bootstrap: String,
    topic: String,
    group: String,
    security_protocol: String,
    ssl_ca_location: Option<String>,
    sasl_mechanism: Option<String>,
    sasl_username: Option<String>,
    sasl_password: Option<String>,
}
impl Options {
    fn config(&self) -> ClientConfig {
        let mut config = ClientConfig::new();
        config
            .set("bootstrap.servers", &self.bootstrap)
            .set("client.id", "rootyard-wake-v1")
            .set("security.protocol", &self.security_protocol)
            .set("allow.auto.create.topics", "false")
            .set("socket.timeout.ms", "1000")
            .set("socket.connection.setup.timeout.ms", "1000")
            .set("reconnect.backoff.ms", "250")
            .set("reconnect.backoff.max.ms", "1000")
            .set("topic.metadata.refresh.interval.ms", "5000")
            .set("metadata.max.age.ms", "5000")
            .set("message.max.bytes", "4096")
            .set("receive.message.max.bytes", "65536");
        if let Some(ca) = &self.ssl_ca_location {
            config.set("ssl.ca.location", ca)
                .set("enable.ssl.certificate.verification", "true")
                .set("ssl.endpoint.identification.algorithm", "https");
        }
        if let (Some(mechanism), Some(user), Some(password)) = (
            &self.sasl_mechanism, &self.sasl_username, &self.sasl_password,
        ) {
            config.set("sasl.mechanism", mechanism)
                .set("sasl.username", user)
                .set("sasl.password", password);
        }
        config
    }
}
#[derive(Default)]
struct QuietContext;
impl ClientContext for QuietContext {
    fn log(&self, _: RDKafkaLogLevel, _: &str, _: &str) {}
    fn error(&self, _: KafkaError, _: &str) {}
}
struct SubscriberContext {
    signal: Arc<Notify>,
    failed: AtomicBool,
}
impl ClientContext for SubscriberContext {
    fn log(&self, _: RDKafkaLogLevel, _: &str, _: &str) {}
    fn error(&self, _: KafkaError, _: &str) {
        if !self.failed.swap(true, Ordering::Relaxed) {
            eprintln!("rootyard: Kafka wake unavailable; PostgreSQL polling continues");
        }
    }
}
impl ConsumerContext for SubscriberContext {
    fn post_rebalance(&self, _: &BaseConsumer<Self>, rebalance: &Rebalance<'_>) {
        if matches!(rebalance, Rebalance::Assign(_)) {
            self.failed.store(false, Ordering::Relaxed);
            self.signal.notify_one();
        }
    }
}
pub struct KafkaWake {
    options: Options,
    producer: OnceCell<ProducerHandle>,
}
impl KafkaWake {
    pub fn new(bootstrap: String, topic: String, group: String) -> Result<Self> {
        ensure!(
            valid_name(&topic) && !topic.starts_with("__") && valid_name(&group),
            "invalid Kafka topic or group name"
        );
        let protocol = std::env::var("ROOTYARD_KAFKA_SECURITY_PROTOCOL")
            .unwrap_or_else(|_| "PLAINTEXT".into());
        ensure!(matches!(protocol.as_str(), "PLAINTEXT" | "SSL" | "SASL_SSL"),
            "unsupported Kafka security protocol");
        let tls = protocol != "PLAINTEXT";
        let ca = if tls {
            let ca = std::env::var("ROOTYARD_KAFKA_CA_PEM")
                .context("Kafka TLS requires ROOTYARD_KAFKA_CA_PEM")?;
            ensure!(std::path::Path::new(&ca).is_file(), "Kafka CA file unavailable");
            Some(ca)
        } else { None };
        let (mechanism, username, password) = if protocol == "SASL_SSL" {
            let mechanism = std::env::var("ROOTYARD_KAFKA_SASL_MECHANISM")
                .unwrap_or_else(|_| "SCRAM-SHA-512".into());
            ensure!(matches!(mechanism.as_str(), "SCRAM-SHA-512" | "SCRAM-SHA-256" | "PLAIN"),
                "unsupported Kafka SASL mechanism");
            let username = std::env::var("ROOTYARD_KAFKA_SASL_USERNAME")
                .context("Kafka SASL username required")?;
            let password = std::env::var("ROOTYARD_KAFKA_SASL_PASSWORD")
                .context("Kafka SASL password required")?;
            ensure!(!username.is_empty() && !password.is_empty(), "Kafka SASL credentials cannot be empty");
            (Some(mechanism), Some(username), Some(password))
        } else { (None, None, None) };
        let addresses: Vec<_> = bootstrap.split(',').collect();
        ensure!(
            !addresses.is_empty() && addresses.len() <= 4,
            "Kafka bootstrap requires 1-4 endpoints"
        );
        for address in addresses {
            if !tls {
                let socket: SocketAddr = address.parse()
                    .context("plaintext Kafka bootstrap must use numeric loopback socket addresses")?;
                ensure!(socket.ip().is_loopback() && socket.port() != 0,
                    "plaintext Kafka bootstrap must use nonzero loopback endpoints");
            } else {
                let (host, port) = address.rsplit_once(':').context("Kafka TLS endpoint must include a port")?;
                ensure!(!host.is_empty() && host.len() <= 253 && host.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')),
                    "invalid Kafka TLS hostname");
                ensure!(port.parse::<u16>().is_ok_and(|port| port > 0), "invalid Kafka TLS port");
            }
        }
        Ok(Self {
            options: Options {
                bootstrap,
                topic,
                group,
                security_protocol: protocol,
                ssl_ca_location: ca,
                sasl_mechanism: mechanism,
                sasl_username: username,
                sasl_password: password,
            },
            producer: OnceCell::new(),
        })
    }
    async fn producer(&self) -> Result<&ProducerHandle> {
        self.producer.get_or_try_init(||async {
            let (tx,mut rx)=mpsc::channel::<oneshot::Sender<bool>>(1);
            let stop=CancellationToken::new();
            let thread_stop=stop.clone();
            let options=self.options.clone();
            std::thread::Builder::new().name("rootyard-kafka-publish".into()).spawn(move || {
                let Ok(runtime)=tokio::runtime::Builder::new_current_thread().enable_all().build() else {return;};
                runtime.block_on(async move {
                    let producer:Result<FutureProducer<QuietContext>,_>=options.config()
                        .set("queue.buffering.max.messages","1")
                        .set("queue.buffering.max.kbytes","1")
                        .set("batch.num.messages","1")
                        .set("batch.size","1000")
                        .set("linger.ms","0")
                        .set("message.timeout.ms","1000")
                        .set("request.timeout.ms","1000")
                        .set("acks","1")
                        .set("max.in.flight.requests.per.connection","1")
                        .set("compression.codec","none")
                        .create_with_context(QuietContext);
                    let Ok(producer)=producer else {return;};
                    loop {
                        let reply=tokio::select! {biased;
                            _=thread_stop.cancelled()=>break,
                            value=rx.recv()=>match value {Some(value)=>value,None=>break},
                        };
                        let record=FutureRecord::<str,[u8]>::to(&options.topic).payload(b"v1");
                        let delivered=tokio::select! {biased;
                            _=thread_stop.cancelled()=>break,
                            result=producer.send(record,Timeout::After(Duration::ZERO))=>result.is_ok(),
                        };
                        let _=reply.send(delivered);
                    }
                    // All native producer destruction stays off the application's runtime.
                    drop(producer);
                });
            }).context("Kafka publisher thread unavailable")?;
            Ok::<_,anyhow::Error>(ProducerHandle{tx,stop})
        }).await
    }
}
struct ProducerHandle {
    tx: mpsc::Sender<oneshot::Sender<bool>>,
    stop: CancellationToken,
}
impl Drop for ProducerHandle {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}
/// Native Kafka close can wait for group networking. Keep poll and destruction
/// on one dedicated OS thread, never blocking the Tokio delivery worker. The
/// cancellation guard also stops it if the subscription future is dropped.
struct StopOnDrop(CancellationToken);
impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
impl WakeTransport for KafkaWake {
    fn publish(&self) -> Task<'_, Result<()>> {
        Box::pin(async move {
            let producer = self.producer().await?;
            let (reply, result) = oneshot::channel();
            producer
                .tx
                .try_send(reply)
                .map_err(|_| anyhow::anyhow!("Kafka wake mailbox unavailable"))?;
            ensure!(
                result.await.unwrap_or(false),
                "Kafka wake delivery unavailable"
            );
            Ok(())
        })
    }
    fn subscribe(&self, signal: Arc<Notify>, stop: CancellationToken) -> Task<'_, ()> {
        Box::pin(async move {
            let thread_stop = stop.child_token();
            let _guard = StopOnDrop(thread_stop.clone());
            let options = self.options.clone();
            let (finished_tx, finished_rx) = oneshot::channel();
            let started=std::thread::Builder::new().name("rootyard-kafka-wake".into()).spawn(move || {
            let context=SubscriberContext{signal:signal.clone(),failed:AtomicBool::new(false)};
            let consumer:Result<BaseConsumer<SubscriberContext>,_>=options.config()
                .set("group.id",&options.group)
                .set("group.protocol","classic")
                .set("partition.assignment.strategy","cooperative-sticky")
                .set("session.timeout.ms","6000")
                .set("heartbeat.interval.ms","1000")
                .set("max.poll.interval.ms","10000")
                // These offsets concern advisory hints only, never PG effects.
                .set("enable.auto.commit","true")
                .set("auto.commit.interval.ms","1000")
                .set("enable.auto.offset.store","true")
                .set("auto.offset.reset","latest")
                .set("queued.min.messages","1")
                .set("queued.max.messages.kbytes","64")
                .set("fetch.max.bytes","32768")
                .set("max.partition.fetch.bytes","4096")
                .set("fetch.wait.max.ms","100")
                .create_with_context(context);
            match consumer {
                Ok(consumer)=>{
                    if consumer.subscribe(&[&options.topic]).is_ok() {
                        while !thread_stop.is_cancelled() {
                            if let Some(Ok(message))=consumer.poll(Duration::from_millis(100)) {
                                if valid_hint(message.payload(),message.key(),message.headers().map_or(0,Headers::count)) {
                                    signal.notify_one();
                                }
                            }
                        }
                        consumer.unsubscribe();
                    } else {
                        eprintln!("rootyard: Kafka subscription unavailable; PostgreSQL polling continues");
                    }
                    // Drop occurs on this OS thread; no await holds a PG lock.
                    drop(consumer);
                }
                Err(_)=>eprintln!("rootyard: Kafka consumer configuration failed; PostgreSQL polling continues"),
            }
            let _=finished_tx.send(());
        });
            if started.is_err() {
                eprintln!(
                    "rootyard: Kafka consumer thread unavailable; PostgreSQL polling continues"
                );
                return;
            }
            tokio::select! { _=stop.cancelled()=>{}, _=finished_rx=>{} }
        })
    }
}
fn valid_hint(payload: Option<&[u8]>, key: Option<&[u8]>, headers: usize) -> bool {
    payload == Some(b"v1".as_slice()) && key.is_none() && headers == 0
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn names_endpoints_and_payloads_are_closed() {
        for name in ["", ".", "..", "bad space", "bad/secret", &"x".repeat(129)] {
            assert!(!valid_name(name));
        }
        assert!(valid_name("rootyard.wake_test-v1"));
        assert!(
            KafkaWake::new(
                "127.0.0.1:9092".into(),
                "__consumer_offsets".into(),
                "group".into()
            )
            .is_err()
        );
        for endpoint in [
            "remote.example:9092",
            "0.0.0.0:9092",
            "127.0.0.1:0",
            "127.0.0.1:9092,",
        ] {
            assert!(KafkaWake::new(endpoint.into(), "wake".into(), "group".into()).is_err());
        }
        assert!(
            KafkaWake::new(
                "127.0.0.1:9092,[::1]:9093".into(),
                "wake".into(),
                "group".into()
            )
            .is_ok()
        );
        assert!(valid_hint(Some(b"v1"), None, 0));
        for payload in [
            None,
            Some(b"".as_slice()),
            Some(b"v2"),
            Some(b"{\"event\":\"forged\"}"),
            Some(&vec![b'x'; 65536]),
        ] {
            assert!(!valid_hint(payload, None, 0));
        }
        assert!(!valid_hint(Some(b"v1"), Some(b""), 0));
        assert!(!valid_hint(Some(b"v1"), None, 1));
    }
    #[tokio::test(flavor = "current_thread")]
    async fn native_cleanup_does_not_block_application_runtime() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener); // deliberately unavailable broker
        let adapter =
            Arc::new(KafkaWake::new(address.to_string(), "wake".into(), "group".into()).unwrap());
        let stop = CancellationToken::new();
        let subscriber_adapter = adapter.clone();
        let subscriber_stop = stop.clone();
        let subscriber = tokio::spawn(async move {
            subscriber_adapter
                .subscribe(Arc::new(Notify::new()), subscriber_stop)
                .await
        });
        let publisher_adapter = adapter.clone();
        let publisher = tokio::spawn(async move { publisher_adapter.publish().await });
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(adapter.producer.get().is_some());
        let started = std::time::Instant::now();
        stop.cancel();
        publisher.abort();
        let _ = publisher.await;
        tokio::time::timeout(Duration::from_secs(1), subscriber)
            .await
            .unwrap()
            .unwrap();
        drop(adapter);
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "native cleanup blocked the single-thread application runtime"
        );
        // Native cleanup may still run on its one dedicated thread. This tests
        // runtime isolation, not a hard wallclock bound on native destruction.
    }
}
