# Using raw QUIC connections with libp2p

This example how to use libp2p's hole punching capabilities to establish a direction raw QUIC connection (i.e. a quic-go `quic.Connection`) to a peer.

## Usage

Run a server behind a NAT (and enable logging for hole punching):
```sh
GOLOG_LOG_LEVEL="p2p-holepunch=debug" go run server/main.go
```

Run a client that connects to the server:
```sh
GOLOG_LOG_LEVEL="p2p-holepunch=debug" go run client.go <peer-id>
```
