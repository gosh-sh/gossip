use std::collections::HashSet;
use std::sync::Arc;

use rustls::CertificateError;
use rustls::DigitallySignedStruct;
use rustls::DistinguishedName;
use rustls::PeerIncompatible;
use rustls::SignatureScheme;
use rustls::client::danger::HandshakeSignatureValid;
use rustls::client::danger::ServerCertVerified;
use rustls::client::danger::ServerCertVerifier;
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::crypto::verify_tls13_signature_with_raw_key;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::ServerName;
use rustls::pki_types::SubjectPublicKeyInfoDer;
use rustls::pki_types::UnixTime;
use rustls::server::danger::ClientCertVerified;
use rustls::server::danger::ClientCertVerifier;

/// Verifies the tls handshake signature of the server,
/// and that the server's raw public key is in the list of trusted keys.
///
/// Note: when the verifier is used for Raw Public Keys the `CertificateDer`
/// argument to the functions contains the SPKI instead of a X509 Certificate
#[derive(Debug)]
pub struct RpkServerCertVerifier {
    trusted_spki: HashSet<Vec<u8>>,
    supported_algs: WebPkiSupportedAlgorithms,
}

impl RpkServerCertVerifier {
    pub fn new(
        trusted_spki_iterable: impl IntoIterator<Item = SubjectPublicKeyInfoDer<'static>>,
    ) -> Self {
        let trusted_spki = trusted_spki_iterable.into_iter().map(|spki| spki.to_vec()).collect();

        RpkServerCertVerifier {
            trusted_spki,
            supported_algs: Arc::new(rustls::crypto::aws_lc_rs::default_provider())
                .clone()
                .signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for RpkServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let end_entity_as_spki = SubjectPublicKeyInfoDer::from(end_entity.as_ref());
        match self.trusted_spki.contains(end_entity_as_spki.as_ref()) {
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

    fn root_hint_subjects(&self) -> Option<&[rustls::DistinguishedName]> {
        None
    }
}

/// Verifies the tls handshake signature of the client,
/// and that the client's raw public key is in the list of trusted keys.
///
/// Note: when the verifier is used for Raw Public Keys the `CertificateDer`
/// argument to the functions contains the SPKI instead of a X509 Certificate
#[derive(Debug)]
pub struct RpkClientCertVerifier {
    trusted_spki: HashSet<Vec<u8>>,
    supported_algs: WebPkiSupportedAlgorithms,
}

impl RpkClientCertVerifier {
    pub fn new(trusted_spki: impl IntoIterator<Item = SubjectPublicKeyInfoDer<'static>>) -> Self {
        let trusted_spki = trusted_spki.into_iter().map(|spki| spki.to_vec()).collect();
        Self {
            trusted_spki,
            supported_algs: Arc::new(rustls::crypto::aws_lc_rs::default_provider())
                .clone()
                .signature_verification_algorithms,
        }
    }
}

impl ClientCertVerifier for RpkClientCertVerifier {
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
        match self.trusted_spki.contains(&end_entity_as_spki[..]) {
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
