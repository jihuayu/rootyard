//! Ephemeral X.509 mTLS PKI fixture generator backed by `rcgen` for multi-process Raft tests.

use std::path::{Path, PathBuf};

use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair};

use rootyard_refcas_log::mtls::{CLIENT_DNS_NAME, MtlsClient, MtlsPaths, node_dns_name};

pub struct ClusterPki {
    dir: tempfile::TempDir,
    ca_cert_path: PathBuf,
    ca_key: KeyPair,
    ca_params: CertificateParams,
    client_paths: MtlsPaths,
}

impl ClusterPki {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("create pki tempdir");
        let (ca_key, ca_params, ca_cert_path) = write_ca(dir.path(), "refcas-cluster-ca");
        let issuer = CertifiedIssuer::self_signed(ca_params.clone(), clone_key(&ca_key)).expect("sign cluster ca");
        let client_paths = write_leaf(dir.path(), "client", &issuer, &ca_cert_path, CLIENT_DNS_NAME);
        Self { dir, ca_cert_path, ca_key, ca_params, client_paths }
    }

    pub fn node_paths(&self, node_id: u64) -> MtlsPaths {
        let cert = self.dir.path().join(format!("node-{node_id}.crt"));
        let key = self.dir.path().join(format!("node-{node_id}.key"));
        if cert.exists() && key.exists() {
            return MtlsPaths { ca_cert: self.ca_cert_path.clone(), cert, key };
        }
        let issuer =
            CertifiedIssuer::self_signed(self.ca_params.clone(), clone_key(&self.ca_key)).expect("rebuild cluster ca");
        write_leaf(self.dir.path(), &format!("node-{node_id}"), &issuer, &self.ca_cert_path, &node_dns_name(node_id))
    }

    pub fn client(&self) -> MtlsClient {
        MtlsClient::from_paths(&self.client_paths).expect("build test mTLS client")
    }
}

pub fn write_ca(dir: &Path, name: &str) -> (KeyPair, CertificateParams, PathBuf) {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("gen ca key");
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(rcgen::DnType::CommonName, name);
    let issuer = CertifiedIssuer::self_signed(params.clone(), clone_key(&key)).expect("self sign ca");
    let ca_path = dir.join(format!("{name}.crt"));
    std::fs::write(&ca_path, issuer.pem()).expect("write ca pem");
    (key, params, ca_path)
}

pub fn write_leaf(dir: &Path, stem: &str, ca: &CertifiedIssuer<'_, KeyPair>, ca_path: &Path, dns: &str) -> MtlsPaths {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("gen leaf key");
    let mut params = CertificateParams::new(vec![dns.to_owned()]).expect("leaf san params");
    params.is_ca = IsCa::ExplicitNoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];
    let cert = params.signed_by(&key, ca).expect("sign leaf cert");
    let cert_path = dir.join(format!("{stem}.crt"));
    let key_path = dir.join(format!("{stem}.key"));
    std::fs::write(&cert_path, cert.pem()).expect("write leaf cert");
    std::fs::write(&key_path, key.serialize_pem()).expect("write leaf key");
    MtlsPaths { ca_cert: ca_path.to_path_buf(), cert: cert_path, key: key_path }
}

fn clone_key(key: &KeyPair) -> KeyPair {
    KeyPair::from_pem(&key.serialize_pem()).expect("roundtrip rcgen keypair")
}
