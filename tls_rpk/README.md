# TLS Raw Public Key (RPK) Implementation

This library implements TLS 1.3 with Raw Public Key (RPK) authentication using ed25519 keys. Instead of using X.509 certificates, this implementation uses raw public keys for mutual authentication between client and server.

## How it Works

The implementation uses ed25519 keys for both client and server authentication. Each party maintains a whitelist of trusted public keys and verifies the peer's identity during the TLS handshake.

### Connection Flow

The following sequence diagram illustrates the TLS handshake and data exchange process:

```mermaid
sequenceDiagram
    participant I as Distribution Mechanism <br/>(e.g. blockchain or The New York Times)
    participant C as Client
    participant S as Server

    C->>C: Load key pair
    S->>S: Load key pair

    I->>S: DB of pubkeys
    I->>C: DB of pubkeys

    Note over C,S: convert only storage format not the key itself
    C->>C: ed25519 server pubkey -> pkcs8 Verifing key (rfc7250) TLS 1.3
    S->>S: ed25519 client pubkey -> pkcs8 Verifing key (rfc7250) TLS 1.3

    Note over C,S: Setup Phase
    C->>C: Create QUIC client_config with server pubkey pksc8
    S->>S: Create QUIC server_config with client pubkey pksc8

    Note over C,S: standard TLS Handshake loop<br/> (until both sides agree on<br/> a common symmetric cypher)
    loop while not server.has_handshake or not client.has_handshake
        C->>S: write_tls("") // headers only
        S->>S: process_new_packets
        S->>C: write_tls("") // headers only
        C->>C: process_new_packets
    end

    Note over C,S: At this point, client and server should<br/> have a common symmetric cypher<br/> which is used under rtt0 protocol

    Note over C,S: Application Data Exchange
    C->>S: write_tls("Hello")
    S->>S: process_new_packets
    S->>S: read message "Hello"

    S->>C: write_tls("world!")
    C->>C: process_new_packets
    C->>C: read message "world!"
```
