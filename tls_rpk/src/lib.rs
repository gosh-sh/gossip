//! This module provides tests for the interoperability of raw public keys with OpenSSL, and also
//! demonstrates how to set up a client-server architecture that utilizes raw public keys.
//!
//! The module also includes example implementations of the `ServerCertVerifier` and `ClientCertVerifier` traits, using
//! pre-configured raw public keys for the verification of the peer.

pub mod config;
pub mod verifier;

pub mod client {
    use std::io::Read;
    use std::io::Write;
    use std::io::{self};
    use std::net::TcpStream;
    use std::sync::Arc;

    use rustls::CertificateError;
    use rustls::ClientConfig;
    use rustls::ClientConnection;
    use rustls::DigitallySignedStruct;
    use rustls::Error;
    use rustls::InconsistentKeys;
    use rustls::PeerIncompatible;
    use rustls::SignatureScheme;
    use rustls::Stream;
    use rustls::client::AlwaysResolvesClientRawPublicKeys;
    use rustls::client::danger::HandshakeSignatureValid;
    use rustls::client::danger::ServerCertVerified;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::crypto::WebPkiSupportedAlgorithms;
    use rustls::crypto::aws_lc_rs as provider;
    use rustls::crypto::verify_tls13_signature_with_raw_key;
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::PrivateKeyDer;
    use rustls::pki_types::ServerName;
    use rustls::pki_types::SubjectPublicKeyInfoDer;
    use rustls::pki_types::UnixTime;
    use rustls::pki_types::pem::PemObject;
    use rustls::sign::CertifiedKey;
    use rustls::version::TLS13;

    /// Build a `ClientConfig` with the given client private key and a server public key to trust.
    pub fn make_config(client_private_key: &str, server_pub_key: &str) -> ClientConfig {
        let client_private_key = Arc::new(provider::default_provider())
            .key_provider
            .load_private_key(
                PrivateKeyDer::from_pem_file(client_private_key)
                    .expect("cannot open private key file"),
            )
            .expect("cannot load signing key");
        let client_public_key = client_private_key
            .public_key()
            .ok_or(Error::InconsistentKeys(InconsistentKeys::Unknown))
            .expect("cannot load public key");
        let client_public_key_as_cert = CertificateDer::from(client_public_key.to_vec());

        let server_raw_key = SubjectPublicKeyInfoDer::from_pem_file(server_pub_key)
            .expect("cannot open pub key file");

        let certified_key =
            Arc::new(CertifiedKey::new(vec![client_public_key_as_cert], client_private_key));

        ClientConfig::builder_with_protocol_versions(&[&TLS13])
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SimpleRpkServerCertVerifier::new(vec![
                server_raw_key,
            ])))
            .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(
                certified_key,
            )))
    }

    /// Run the client and connect to the server at the specified port.
    ///
    /// This client reads a message and then writes 'Hello from the client' to the server.
    pub fn run_client(config: ClientConfig, port: u16) -> Result<String, io::Error> {
        let server_name = "0.0.0.0".try_into().unwrap();
        let mut conn = ClientConnection::new(Arc::new(config), server_name).unwrap();
        let mut sock = TcpStream::connect(format!("[::]:{port}")).unwrap();
        let mut tls = Stream::new(&mut conn, &mut sock);

        let mut buf = vec![0; 128];
        let len = tls.read(&mut buf).unwrap();
        let received_message = String::from_utf8_lossy(&buf[..len]).to_string();

        let bytes_written = tls.write("Hello from the client".as_bytes()).unwrap_or("".len());
        assert!(bytes_written > 0);
        Ok(received_message)
    }

    /// Verifies the tls handshake signature of the server,
    /// and that the server's raw public key is in the list of trusted keys.
    ///
    /// Note: when the verifier is used for Raw Public Keys the `CertificateDer` argument to the functions contains the SPKI instead of a X509 Certificate
    #[derive(Debug)]
    pub struct SimpleRpkServerCertVerifier {
        trusted_spki: Vec<SubjectPublicKeyInfoDer<'static>>,
        supported_algs: WebPkiSupportedAlgorithms,
    }

    impl SimpleRpkServerCertVerifier {
        pub fn new(trusted_spki: Vec<SubjectPublicKeyInfoDer<'static>>) -> Self {
            SimpleRpkServerCertVerifier {
                trusted_spki,
                supported_algs: Arc::new(provider::default_provider())
                    .clone()
                    .signature_verification_algorithms,
            }
        }
    }

    impl ServerCertVerifier for SimpleRpkServerCertVerifier {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            let end_entity_as_spki = SubjectPublicKeyInfoDer::from(end_entity.as_ref());
            match self.trusted_spki.contains(&end_entity_as_spki) {
                false => Err(rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer)),
                true => Ok(ServerCertVerified::assertion()),
            }
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Err(rustls::Error::PeerIncompatible(PeerIncompatible::Tls12NotOffered))
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls13_signature_with_raw_key(
                message,
                &SubjectPublicKeyInfoDer::from(cert.as_ref()),
                dss,
                &self.supported_algs,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.supported_algs.supported_schemes()
        }

        fn requires_raw_public_keys(&self) -> bool {
            true
        }
    }
}

pub mod server {
    use std::io::ErrorKind;
    use std::io::Read;
    use std::io::Write;
    use std::io::{self};
    use std::net::TcpListener;
    use std::sync::Arc;

    use rustls::CertificateError;
    use rustls::DigitallySignedStruct;
    use rustls::DistinguishedName;
    use rustls::Error;
    use rustls::InconsistentKeys;
    use rustls::PeerIncompatible;
    use rustls::ServerConfig;
    use rustls::ServerConnection;
    use rustls::SignatureScheme;
    use rustls::client::danger::HandshakeSignatureValid;
    use rustls::crypto::WebPkiSupportedAlgorithms;
    use rustls::crypto::aws_lc_rs as provider;
    use rustls::crypto::verify_tls13_signature_with_raw_key;
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::PrivateKeyDer;
    use rustls::pki_types::SubjectPublicKeyInfoDer;
    use rustls::pki_types::UnixTime;
    use rustls::pki_types::pem::PemObject;
    use rustls::server::AlwaysResolvesServerRawPublicKeys;
    use rustls::server::danger::ClientCertVerified;
    use rustls::server::danger::ClientCertVerifier;
    use rustls::sign::CertifiedKey;
    use rustls::version::TLS13;

    /// Build a `ServerConfig` with the given server private key and a client public key to trust.
    pub fn make_config(server_private_key: &str, client_pub_key: &str) -> ServerConfig {
        let client_raw_key = SubjectPublicKeyInfoDer::from_pem_file(client_pub_key)
            .expect("cannot open pub key file");

        let server_private_key = provider::default_provider()
            .key_provider
            .load_private_key(
                PrivateKeyDer::from_pem_file(server_private_key)
                    .expect("cannot open private key file"),
            )
            .expect("cannot load signing key");
        let server_public_key = server_private_key
            .public_key()
            .ok_or(Error::InconsistentKeys(InconsistentKeys::Unknown))
            .expect("cannot load public key");
        let server_public_key_as_cert = CertificateDer::from(server_public_key.to_vec());

        let certified_key =
            Arc::new(CertifiedKey::new(vec![server_public_key_as_cert], server_private_key));

        let client_cert_verifier = Arc::new(SimpleRpkClientCertVerifier::new(vec![client_raw_key]));
        let server_cert_resolver = Arc::new(AlwaysResolvesServerRawPublicKeys::new(certified_key));

        ServerConfig::builder_with_protocol_versions(&[&TLS13])
            .with_client_cert_verifier(client_cert_verifier)
            .with_cert_resolver(server_cert_resolver)
    }

    /// Run the server at the specified port and accept a connection from the client.
    ///
    /// After the handshake is complete, the server writes 'Hello from the server' to the client.
    /// The server then waits until reads it receives a message from the client and closes the connection.
    pub fn run_server(config: ServerConfig, listener: TcpListener) -> Result<String, io::Error> {
        let (mut stream, _) = listener.accept()?;

        let mut conn = ServerConnection::new(Arc::new(config)).unwrap();
        conn.complete_io(&mut stream)?;

        conn.writer().write_all(b"Hello from the server")?;
        conn.complete_io(&mut stream)?;

        let mut buf = [0; 128];

        loop {
            match conn.reader().read(&mut buf) {
                Ok(len) => {
                    conn.send_close_notify();
                    conn.complete_io(&mut stream)?;
                    return Ok(String::from_utf8_lossy(&buf[..len]).to_string());
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => {
                    conn.read_tls(&mut stream)?;
                    conn.process_new_packets().unwrap();
                }
                Err(err) => {
                    return Err(err);
                }
            };
        }
    }

    /// Verifies the tls handshake signature of the client,
    /// and that the client's raw public key is in the list of trusted keys.
    ///
    /// Note: when the verifier is used for Raw Public Keys the `CertificateDer` argument to the functions contains the SPKI instead of a X509 Certificate
    #[derive(Debug)]
    pub struct SimpleRpkClientCertVerifier {
        trusted_spki: Vec<SubjectPublicKeyInfoDer<'static>>,
        supported_algs: WebPkiSupportedAlgorithms,
    }

    impl SimpleRpkClientCertVerifier {
        pub fn new(trusted_spki: Vec<SubjectPublicKeyInfoDer<'static>>) -> Self {
            Self {
                trusted_spki,
                supported_algs: Arc::new(provider::default_provider())
                    .clone()
                    .signature_verification_algorithms,
            }
        }
    }

    impl ClientCertVerifier for SimpleRpkClientCertVerifier {
        fn root_hint_subjects(&self) -> &[DistinguishedName] {
            &[]
        }

        fn verify_client_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _now: UnixTime,
        ) -> Result<ClientCertVerified, rustls::Error> {
            let end_entity_as_spki = SubjectPublicKeyInfoDer::from(end_entity.as_ref());
            match self.trusted_spki.contains(&end_entity_as_spki) {
                false => Err(rustls::Error::InvalidCertificate(CertificateError::UnknownIssuer)),
                true => Ok(ClientCertVerified::assertion()),
            }
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Err(rustls::Error::PeerIncompatible(PeerIncompatible::Tls12NotOffered))
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls13_signature_with_raw_key(
                message,
                &SubjectPublicKeyInfoDer::from(cert.as_ref()),
                dss,
                &self.supported_algs,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.supported_algs.supported_schemes()
        }

        fn requires_raw_public_keys(&self) -> bool {
            true
        }
    }
}
