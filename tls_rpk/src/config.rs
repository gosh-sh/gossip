use std::sync::Arc;

use ::rustls::client::AlwaysResolvesClientRawPublicKeys;
use ed25519_dalek::ed25519;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::pkcs8::spki::der::Encode;
use rustls::ClientConfig;
use rustls::InconsistentKeys;
use rustls::ServerConfig;
use rustls::crypto::KeyProvider;
use rustls::crypto::aws_lc_rs;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::pki_types::SubjectPublicKeyInfoDer;
use rustls::server::AlwaysResolvesServerRawPublicKeys;
use rustls::sign::CertifiedKey;

use crate::verifier::RpkClientCertVerifier;
use crate::verifier::RpkServerCertVerifier;

pub fn generate_cert(
    key: ed25519_dalek::SigningKey,
    key_provider: &dyn KeyProvider,
) -> anyhow::Result<Arc<CertifiedKey>> {
    let pkcs8 = key.to_pkcs8_der()?;
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8.as_bytes().to_vec()));
    let server_private_key = key_provider.load_private_key(key_der)?;
    let server_public_key = server_private_key
        .public_key()
        .ok_or(rustls::Error::InconsistentKeys(InconsistentKeys::Unknown))
        .expect("cannot load public key");
    let server_public_key_as_cert = CertificateDer::from(server_public_key.to_vec());

    let certified_key =
        Arc::new(CertifiedKey::new(vec![server_public_key_as_cert], server_private_key));

    Ok(certified_key)
}

pub fn server_config(
    secret_key: ed25519_dalek::SigningKey,
    whitelist: Vec<SubjectPublicKeyInfoDer<'static>>,
) -> anyhow::Result<ServerConfig> {
    let client_verifier = Arc::new(RpkClientCertVerifier::new(whitelist));

    let cert_key =
        generate_cert(secret_key, rustls::crypto::aws_lc_rs::default_provider().key_provider)?;
    let server_cert_resolver = Arc::new(AlwaysResolvesServerRawPublicKeys::new(cert_key));

    let server = ServerConfig::builder_with_protocol_versions(&[&::rustls::version::TLS13])
        .with_client_cert_verifier(client_verifier)
        .with_cert_resolver(server_cert_resolver);

    Ok(server)
}

pub fn client_config(
    secret_key: ed25519_dalek::SigningKey,
    whitelist: Vec<SubjectPublicKeyInfoDer<'static>>,
) -> anyhow::Result<ClientConfig> {
    aws_lc_rs::default_provider().install_default().ok();

    let server_verifier = Arc::new(RpkServerCertVerifier::new(whitelist));

    let cert_key =
        generate_cert(secret_key, rustls::crypto::aws_lc_rs::default_provider().key_provider)?;
    let client_cert_resolver = Arc::new(AlwaysResolvesClientRawPublicKeys::new(cert_key));

    let client = ClientConfig::builder_with_protocol_versions(&[&::rustls::version::TLS13])
        .dangerous()
        .with_custom_certificate_verifier(server_verifier)
        .with_client_cert_resolver(client_cert_resolver);

    Ok(client)
}

pub fn ed25519_pubkey_to_spki(
    key: &ed25519_dalek::VerifyingKey,
) -> SubjectPublicKeyInfoDer<'static> {
    use ed25519_dalek::pkcs8::EncodePublicKey;
    let pkbytes = ed25519::PublicKeyBytes::from(key);
    let spki = pkbytes.to_public_key_der().unwrap().to_der().unwrap();
    SubjectPublicKeyInfoDer::from(spki)
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::io::Write;

    use rustls::ClientConnection;
    use rustls::ServerConnection;

    use super::*;

    fn generate_signing_key() -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng {})
    }

    #[test]
    fn test_simple_connection() {
        // aws_lc_rs::default_provider().install_default();

        let server_signing_key = generate_signing_key();
        let client_signing_key = generate_signing_key();

        let whitelist_for_server = [client_signing_key.verifying_key()]
            .into_iter()
            .map(|key| ed25519_pubkey_to_spki(&key.to_owned()))
            .collect::<Vec<_>>();

        let whitelist_for_client = [server_signing_key.verifying_key()]
            .into_iter()
            .map(|key| ed25519_pubkey_to_spki(&key.to_owned()))
            .collect::<Vec<_>>();

        let client_config = client_config(client_signing_key, whitelist_for_client).unwrap();
        let server_config = server_config(server_signing_key, whitelist_for_server).unwrap();

        let mut client = ClientConnection::new(
            Arc::new(client_config),
            rustls::pki_types::ServerName::try_from("test").unwrap(),
        )
        .unwrap();
        let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

        let mut client_to_server = Vec::new();
        let mut server_to_client = Vec::new();

        // Complete handshake first
        while client.is_handshaking() || server.is_handshaking() {
            // Client -> Server
            client.write_tls(&mut client_to_server).unwrap();
            server.read_tls(&mut &client_to_server[..]).unwrap();
            server.process_new_packets().unwrap();
            client_to_server.clear();

            // Server -> Client
            server.write_tls(&mut server_to_client).unwrap();
            client.read_tls(&mut &server_to_client[..]).unwrap();
            client.process_new_packets().unwrap();
            server_to_client.clear();
        }

        // Now exchange application data
        let client_message = b"Hello";
        client.writer().write_all(client_message).unwrap();
        client.write_tls(&mut client_to_server).unwrap();

        server.read_tls(&mut &client_to_server[..]).unwrap();
        server.process_new_packets().unwrap();

        let mut received = Vec::new();
        let mut buf = [0u8; 1024];
        let n = server.reader().read(&mut buf).unwrap();
        received.extend_from_slice(dbg!(&buf[..n]));
        assert_eq!(&received, client_message);

        // Server sends response
        let server_message = b"world!";
        server.writer().write_all(server_message).unwrap();
        server.write_tls(&mut server_to_client).unwrap();

        // Client reads server's response
        client.read_tls(&mut &server_to_client[..]).unwrap();
        client.process_new_packets().unwrap();

        let mut received = Vec::new();
        let mut buf = [0u8; 1024];
        let n = client.reader().read(&mut buf).unwrap();
        received.extend_from_slice(dbg!(&buf[..n]));
        assert_eq!(&received, server_message);
    }
}
