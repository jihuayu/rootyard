//! Streaming, content-addressed object storage shared by pack, LFS and workspace publishers.
//! Keys are tenant-scoped and immutable; callers publish their database manifests only
//! after `put_file` and a verifying read complete.
use anyhow::{Context, Result, bail, ensure};
use futures_util::StreamExt;
use hmac::{Hmac, Mac};
use reqwest::{Client, Method, StatusCode, Url, header};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncWriteExt},
    time::Instant,
};
use tokio_util::io::ReaderStream;
use uuid::Uuid;

const PART_BYTES: u64 = 8 * 1024 * 1024;
const MAX_RANGE_BYTES: u64 = 1024 * 1024;
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug)]
pub struct ObjectKey {
    pub tenant_id: Uuid,
    pub namespace: String,
    pub sha256: String,
}
impl ObjectKey {
    pub fn new(tenant_id: Uuid, namespace: &str, sha256: &str) -> Result<Self> {
        ensure!(!tenant_id.is_nil(), "object key needs a tenant");
        ensure!(
            !namespace.is_empty()
                && namespace.len() <= 48
                && namespace.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
            "invalid object namespace"
        );
        ensure!(
            sha256.len() == 64 && sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid object digest"
        );
        Ok(Self { tenant_id, namespace: namespace.into(), sha256: sha256.into() })
    }
    pub fn path(&self) -> String {
        format!("tenants/{}/{}/{}", self.tenant_id, self.namespace, self.sha256)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredObject {
    pub sha256: String,
    pub size: u64,
}

pub enum RemoteObjectStore {
    Local(PathBuf),
    S3(S3Store),
}

pub struct S3Store {
    client: Client,
    endpoint: Url,
    bucket: String,
    region: String,
    access_key: String,
    secret_key: String,
    session_token: Option<String>,
}

enum Payload {
    FileRange(PathBuf, u64, u64),
    Bytes(Vec<u8>),
}

fn valid_bucket(s: &str) -> bool {
    (3..=63).contains(&s.len())
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        && !s.starts_with('.')
        && !s.ends_with('.')
        && !s.contains("..")
}

impl RemoteObjectStore {
    pub fn from_env(local_root: PathBuf) -> Result<Self> {
        let Ok(endpoint) = std::env::var("ROOTYARD_OBJECT_STORE_ENDPOINT") else {
            return Ok(Self::Local(local_root));
        };
        let endpoint = Url::parse(&endpoint)?;
        let loopback = matches!(endpoint.host_str(), Some("127.0.0.1" | "::1" | "localhost"));
        ensure!(endpoint.scheme() == "https" || endpoint.scheme() == "http" && loopback, "object store requires TLS");
        ensure!(
            endpoint.path() == "/"
                && endpoint.query().is_none()
                && endpoint.fragment().is_none()
                && endpoint.username().is_empty()
                && endpoint.password().is_none(),
            "object store endpoint must be an origin URL"
        );
        let bucket = std::env::var("ROOTYARD_OBJECT_STORE_BUCKET").context("object store bucket missing")?;
        ensure!(valid_bucket(&bucket), "invalid object store bucket");
        let region = std::env::var("ROOTYARD_OBJECT_STORE_REGION").context("object store region missing")?;
        ensure!(
            !region.is_empty() && region.len() <= 64 && region.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "invalid object store region"
        );
        let access_key =
            std::env::var("ROOTYARD_OBJECT_STORE_ACCESS_KEY").context("object store access key missing")?;
        let secret_key =
            std::env::var("ROOTYARD_OBJECT_STORE_SECRET_KEY").context("object store secret key missing")?;
        ensure!(!access_key.is_empty() && !secret_key.is_empty(), "object store credentials missing");
        let session_token = std::env::var("ROOTYARD_OBJECT_STORE_SESSION_TOKEN").ok();
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self::S3(S3Store { client, endpoint, bucket, region, access_key, secret_key, session_token }))
    }

    pub async fn put_file(
        &self,
        key: &ObjectKey,
        source: &Path,
        expected_size: u64,
        deadline: Instant,
    ) -> Result<StoredObject> {
        let actual = hash_file(source, deadline).await?;
        ensure!(actual.size == expected_size && actual.sha256 == key.sha256, "object source digest or size mismatch");
        match self {
            Self::Local(root) => local_put(root, key, source, deadline).await?,
            Self::S3(s3) => s3.put(key, source, expected_size, deadline).await?,
        }
        let head = self.head(key, deadline).await?.context("uploaded object is missing")?;
        ensure!(head.size == expected_size, "uploaded object is truncated");
        let verification = std::env::temp_dir().join(format!("rootyard-verify-{}", Uuid::new_v4()));
        let verified = self.get_to_file(key, &verification, expected_size, deadline).await;
        let _ = fs::remove_file(&verification).await;
        verified?;
        Ok(actual)
    }

    pub async fn head(&self, key: &ObjectKey, deadline: Instant) -> Result<Option<StoredObject>> {
        match self {
            Self::Local(root) => {
                let path = root.join(key.path());
                match fs::metadata(&path).await {
                    Ok(meta) if meta.is_file() => {
                        Ok(Some(StoredObject { sha256: key.sha256.clone(), size: meta.len() }))
                    }
                    Ok(_) => bail!("stored object is not a file"),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                    Err(e) => Err(e.into()),
                }
            }
            Self::S3(s3) => s3.head(key, deadline).await,
        }
    }

    pub async fn get_to_file(
        &self,
        key: &ObjectKey,
        destination: &Path,
        expected_size: u64,
        deadline: Instant,
    ) -> Result<()> {
        let parent = destination.parent().context("object destination parent missing")?;
        fs::create_dir_all(parent).await?;
        let temp = parent.join(format!(".rootyard-object-{}", Uuid::new_v4()));
        let result = async {
            let mut out = fs::OpenOptions::new().write(true).create_new(true).open(&temp).await?;
            let mut hash = Sha256::new();
            let mut size = 0u64;
            match self {
                Self::Local(root) => {
                    let mut input = File::open(root.join(key.path())).await?;
                    let mut buf = [0u8; 64 * 1024];
                    loop {
                        let n = tokio::time::timeout_at(deadline, input.read(&mut buf)).await??;
                        if n == 0 {
                            break;
                        }
                        size += n as u64;
                        ensure!(size <= expected_size, "stored object exceeds expected size");
                        hash.update(&buf[..n]);
                        out.write_all(&buf[..n]).await?;
                    }
                }
                Self::S3(s3) => {
                    let response = s3.send(Method::GET, key, "", None, None, deadline).await?;
                    ensure!(response.status() == StatusCode::OK, "object GET failed: {}", response.status());
                    let mut stream = response.bytes_stream();
                    while let Some(chunk) = tokio::time::timeout_at(deadline, stream.next()).await? {
                        let chunk = chunk?;
                        size += chunk.len() as u64;
                        ensure!(size <= expected_size, "stored object exceeds expected size");
                        hash.update(&chunk);
                        out.write_all(&chunk).await?;
                    }
                }
            }
            ensure!(
                size == expected_size && hex::encode(hash.finalize()) == key.sha256,
                "stored object digest or size mismatch"
            );
            out.sync_all().await?;
            fs::rename(&temp, destination).await?;
            File::open(parent).await?.sync_all().await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        if result.is_err() {
            let _ = fs::remove_file(&temp).await;
        }
        result
    }

    pub async fn get_range(&self, key: &ObjectKey, start: u64, len: u64, deadline: Instant) -> Result<Vec<u8>> {
        ensure!(len <= MAX_RANGE_BYTES && len > 0, "object range exceeds limit");
        let end = start.checked_add(len - 1).context("object range overflow")?;
        match self {
            Self::Local(root) => {
                use tokio::io::AsyncSeekExt;
                let mut file = File::open(root.join(key.path())).await?;
                file.seek(std::io::SeekFrom::Start(start)).await?;
                let mut bytes = vec![0u8; len as usize];
                tokio::time::timeout_at(deadline, file.read_exact(&mut bytes)).await??;
                Ok(bytes)
            }
            Self::S3(s3) => {
                let range = format!("bytes={start}-{end}");
                let response = s3.send(Method::GET, key, "", None, Some((&header::RANGE, &range)), deadline).await?;
                ensure!(
                    response.status() == StatusCode::PARTIAL_CONTENT,
                    "object range GET failed: {}",
                    response.status()
                );
                let mut stream = response.bytes_stream();
                let mut bytes = Vec::with_capacity(len as usize);
                while let Some(chunk) = tokio::time::timeout_at(deadline, stream.next()).await? {
                    let chunk = chunk?;
                    ensure!(chunk.len() <= len as usize - bytes.len(), "object range response exceeds limit");
                    bytes.extend_from_slice(&chunk);
                }
                ensure!(bytes.len() == len as usize, "object range response truncated");
                Ok(bytes)
            }
        }
    }

    pub async fn delete(&self, key: &ObjectKey, deadline: Instant) -> Result<()> {
        match self {
            Self::Local(root) => match fs::remove_file(root.join(key.path())).await {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e.into()),
            },
            Self::S3(s3) => {
                let response = s3.send(Method::DELETE, key, "", None, None, deadline).await?;
                ensure!(response.status().is_success(), "object DELETE failed: {}", response.status());
                Ok(())
            }
        }
    }
}

async fn hash_file(path: &Path, deadline: Instant) -> Result<StoredObject> {
    let mut file = File::open(path).await?;
    let mut hash = Sha256::new();
    let mut size = 0u64;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = tokio::time::timeout_at(deadline, file.read(&mut buf)).await??;
        if n == 0 {
            break;
        }
        size = size.checked_add(n as u64).context("object size overflow")?;
        hash.update(&buf[..n]);
    }
    Ok(StoredObject { sha256: hex::encode(hash.finalize()), size })
}

async fn local_put(root: &Path, key: &ObjectKey, source: &Path, deadline: Instant) -> Result<()> {
    let target = root.join(key.path());
    let parent = target.parent().context("object parent missing")?;
    fs::create_dir_all(parent).await?;
    let temp = parent.join(format!(".tmp-{}", Uuid::new_v4()));
    let result = async {
        let mut input = File::open(source).await?;
        let mut output = fs::OpenOptions::new().write(true).create_new(true).open(&temp).await?;
        tokio::time::timeout_at(deadline, tokio::io::copy(&mut input, &mut output)).await??;
        output.sync_all().await?;
        match fs::hard_link(&temp, &target).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing = hash_file(&target, deadline).await?;
                ensure!(existing.sha256 == key.sha256, "immutable object key collision");
            }
            Err(e) => return Err(e.into()),
        }
        File::open(parent).await?.sync_all().await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    let _ = fs::remove_file(&temp).await;
    result
}

fn percent_encode(value: &str) -> String {
    let mut out = String::new();
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn amz_time() -> Result<(String, String)> {
    let secs = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?.as_secs() as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::gmtime_r(&secs, &mut tm) }.is_null() {
        bail!("UTC clock conversion failed");
    }
    let date = format!("{:04}{:02}{:02}", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
    let timestamp = format!("{}T{:02}{:02}{:02}Z", date, tm.tm_hour, tm.tm_min, tm.tm_sec);
    Ok((date, timestamp))
}

fn hmac(key: &[u8], bytes: &[u8]) -> Result<Vec<u8>> {
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| anyhow::anyhow!("invalid signing key"))?;
    mac.update(bytes);
    Ok(mac.finalize().into_bytes().to_vec())
}

impl S3Store {
    fn url(&self, key: &ObjectKey, query: &str) -> Result<Url> {
        let mut url = self.endpoint.clone();
        url.set_path(&format!("/{}/{}", self.bucket, key.path()));
        if !query.is_empty() {
            url.set_query(Some(query));
        }
        Ok(url)
    }

    fn signed(
        &self,
        method: &Method,
        key: &ObjectKey,
        query: &str,
        extra: Option<(&header::HeaderName, &str)>,
    ) -> Result<reqwest::RequestBuilder> {
        let url = self.url(key, query)?;
        let (date, timestamp) = amz_time()?;
        let mut host = url.host_str().context("object store host missing")?.to_owned();
        if host.contains(':') {
            host = format!("[{host}]");
        }
        if let Some(port) = url.port() {
            host.push_str(&format!(":{port}"));
        }
        let mut headers = vec![
            ("host".to_owned(), host),
            ("x-amz-content-sha256".to_owned(), "UNSIGNED-PAYLOAD".to_owned()),
            ("x-amz-date".to_owned(), timestamp.clone()),
        ];
        if let Some(token) = &self.session_token {
            headers.push(("x-amz-security-token".into(), token.clone()));
        }
        if let Some((name, value)) = extra {
            headers.push((name.as_str().to_owned(), value.to_owned()));
        }
        headers.sort_by(|a, b| a.0.cmp(&b.0));
        let canonical_headers = headers.iter().map(|(k, v)| format!("{k}:{}\n", v.trim())).collect::<String>();
        let signed_headers = headers.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>().join(";");
        let canonical = format!(
            "{}\n{}\n{}\n{}\n{}\nUNSIGNED-PAYLOAD",
            method.as_str(),
            url.path(),
            query,
            canonical_headers,
            signed_headers
        );
        let scope = format!("{date}/{}/s3/aws4_request", self.region);
        let to_sign =
            format!("AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{}", hex::encode(Sha256::digest(canonical.as_bytes())));
        let k_date = hmac(format!("AWS4{}", self.secret_key).as_bytes(), date.as_bytes())?;
        let k_region = hmac(&k_date, self.region.as_bytes())?;
        let k_service = hmac(&k_region, b"s3")?;
        let k_signing = hmac(&k_service, b"aws4_request")?;
        let signature = hex::encode(hmac(&k_signing, to_sign.as_bytes())?);
        let auth = format!(
            "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
            self.access_key
        );
        let mut request = self.client.request(method.clone(), url).header(header::AUTHORIZATION, auth);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        Ok(request)
    }

    async fn send(
        &self,
        method: Method,
        key: &ObjectKey,
        query: &str,
        payload: Option<Payload>,
        extra: Option<(&header::HeaderName, &str)>,
        deadline: Instant,
    ) -> Result<reqwest::Response> {
        let mut last = None;
        for attempt in 0..3 {
            let mut request = self.signed(&method, key, query, extra)?;
            if let Some(body) = &payload {
                request = match body {
                    Payload::FileRange(path, offset, len) => {
                        use tokio::io::AsyncSeekExt;
                        let mut file = File::open(path).await?;
                        file.seek(std::io::SeekFrom::Start(*offset)).await?;
                        request
                            .header(header::CONTENT_LENGTH, *len)
                            .body(reqwest::Body::wrap_stream(ReaderStream::new(file.take(*len))))
                    }
                    Payload::Bytes(bytes) => request.body(bytes.clone()),
                };
            }
            match tokio::time::timeout_at(deadline, request.send()).await {
                Ok(Ok(response)) if !response.status().is_server_error() => return Ok(response),
                Ok(Ok(response)) => last = Some(format!("object store HTTP {}", response.status())),
                Ok(Err(error)) => last = Some(error.to_string()),
                Err(_) => bail!("object store request timed out"),
            }
            if attempt < 2 {
                tokio::time::sleep(Duration::from_millis(100 * (attempt + 1))).await;
            }
        }
        bail!("object store request failed: {}", last.unwrap_or_default())
    }

    async fn head(&self, key: &ObjectKey, deadline: Instant) -> Result<Option<StoredObject>> {
        let response = self.send(Method::HEAD, key, "", None, None, deadline).await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        ensure!(response.status().is_success(), "object HEAD failed: {}", response.status());
        let size =
            response.headers().get(header::CONTENT_LENGTH).context("object HEAD missing length")?.to_str()?.parse()?;
        Ok(Some(StoredObject { sha256: key.sha256.clone(), size }))
    }

    async fn put(&self, key: &ObjectKey, source: &Path, size: u64, deadline: Instant) -> Result<()> {
        if let Some(existing) = self.head(key, deadline).await? {
            ensure!(existing.size == size, "immutable object key collision");
            return Ok(());
        }
        if size <= PART_BYTES {
            let response = self
                .send(
                    Method::PUT,
                    key,
                    "",
                    Some(Payload::FileRange(source.to_owned(), 0, size)),
                    Some((&header::IF_NONE_MATCH, "*")),
                    deadline,
                )
                .await?;
            ensure!(
                response.status().is_success()
                    || response.status() == StatusCode::PRECONDITION_FAILED
                        && self.head(key, deadline).await?.is_some(),
                "object PUT failed: {}",
                response.status()
            );
            return Ok(());
        }
        let initiated = self.send(Method::POST, key, "uploads=", None, None, deadline).await?;
        ensure!(initiated.status().is_success(), "multipart initiation failed: {}", initiated.status());
        let xml = tokio::time::timeout_at(deadline, initiated.text()).await??;
        let upload_id = xml
            .split("<UploadId>")
            .nth(1)
            .and_then(|s| s.split("</UploadId>").next())
            .context("multipart upload id missing")?
            .to_owned();
        ensure!(!upload_id.is_empty() && upload_id.len() <= 2048, "invalid multipart upload id");
        let encoded = percent_encode(&upload_id);
        let mut parts = Vec::new();
        let result = async {
            let mut offset = 0u64;
            while offset < size {
                let number = parts.len() + 1;
                ensure!(number <= 10_000, "too many multipart parts");
                let len = (size - offset).min(PART_BYTES);
                let query = format!("partNumber={number}&uploadId={encoded}");
                let response = self
                    .send(
                        Method::PUT,
                        key,
                        &query,
                        Some(Payload::FileRange(source.to_owned(), offset, len)),
                        None,
                        deadline,
                    )
                    .await?;
                ensure!(response.status().is_success(), "multipart part failed: {}", response.status());
                let etag = response.headers().get(header::ETAG).context("multipart ETag missing")?.to_str()?.to_owned();
                ensure!(etag.starts_with('"') && etag.ends_with('"') && etag.len() < 256, "invalid multipart ETag");
                parts.push((number, etag));
                offset += len;
            }
            let mut body = String::from("<CompleteMultipartUpload>");
            for (number, etag) in &parts {
                body.push_str(&format!("<Part><PartNumber>{number}</PartNumber><ETag>{etag}</ETag></Part>"));
            }
            body.push_str("</CompleteMultipartUpload>");
            let query = format!("uploadId={encoded}");
            let response =
                self.send(Method::POST, key, &query, Some(Payload::Bytes(body.into_bytes())), None, deadline).await?;
            ensure!(response.status().is_success(), "multipart completion failed: {}", response.status());
            let text = tokio::time::timeout_at(deadline, response.text()).await??;
            ensure!(!text.contains("<Error>"), "multipart completion reported an error");
            Ok::<(), anyhow::Error>(())
        }
        .await;
        if result.is_err() {
            let query = format!("uploadId={encoded}");
            let _ = self.send(Method::DELETE, key, &query, None, None, deadline).await;
        }
        result
    }
}
