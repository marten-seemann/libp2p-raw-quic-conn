# Using raw QUIC connections with libp2p

## Usage

Run a server behind a NAT (and enable logging for hole punching):
```sh
GOLOG_LOG_LEVEL="p2p-holepunch=debug" go run server/main.go
```

Run a client that connects to the server:
```sh
GOLOG_LOG_LEVEL="p2p-holepunch=debug" go run client.go <peer-id>
```
