package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"math/big"
	"net"
	"slices"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/protocol/holepunch"
	libp2pquic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	"github.com/libp2p/go-libp2p/p2p/transport/quicreuse"
	ma "github.com/multiformats/go-multiaddr"
	mafmt "github.com/multiformats/go-multiaddr-fmt"
	"github.com/quic-go/quic-go"
)

func main() {
	runServer(12345)
}

func runServer(port int) {
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil {
		log.Fatal("failed to create UDP listener: ", err)
	}
	tr := &quic.Transport{Conn: udpConn}
	newReuse := func(statelessResetKey quic.StatelessResetKey, tokenGeneratorKey quic.TokenGeneratorKey) (*quicreuse.ConnManager, error) {
		reuse, err := quicreuse.NewConnManager(statelessResetKey, tokenGeneratorKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create reuse: %w", err)
		}
		if err := reuse.AddTransport("udp4", &wrappedQUICTransport{tr}, udpConn); err != nil {
			return nil, fmt.Errorf("failed to add transport to reuse: %w", err)
		}
		return reuse, nil
	}
	peerChan := make(chan peer.AddrInfo, 32)
	h, err := libp2p.New(
		libp2p.ForceReachabilityPrivate(),
		libp2p.EnableAutoRelayWithPeerSource(func(context.Context, int) <-chan peer.AddrInfo { return peerChan }),
		libp2p.EnableHolePunching(holepunch.WithAddrFilter(&quicAddrFilter{})),
		libp2p.Transport(libp2pquic.NewTransport),
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/0.0.0.0/udp/%d/quic-v1", port)),
		libp2p.QUICReuse(newReuse),
	)
	if err != nil {
		log.Fatal("failed to create second libp2p host: ", err)
	}
	defer h.Close()
	for _, addr := range h.Addrs() {
		fmt.Printf("listening on %s/p2p/%s\n", addr, h.ID())
	}

	ipfsDHT, err := dht.New(
		context.Background(),
		h,
		dht.Mode(dht.ModeClient),
		dht.BootstrapPeers(dht.GetDefaultBootstrapPeerAddrInfos()...),
	)
	if err != nil {
		log.Fatal("failed to create DHT: ", err)
	}
	defer ipfsDHT.Close()
	if err := ipfsDHT.Bootstrap(context.Background()); err != nil {
		log.Fatal("failed to bootstrap DHT: ", err)
	}
	log.Println("DHT bootstrap complete")

	go func() {
		sub, err := h.EventBus().Subscribe(new(event.EvtPeerConnectednessChanged))
		if err != nil {
			log.Fatal("failed to subscribe to peer connectedness changed event: ", err)
		}
		defer sub.Close()
		for ev := range sub.Out() {
			e := ev.(event.EvtPeerConnectednessChanged)
			if e.Connectedness == network.Connected {
				select {
				case peerChan <- peer.AddrInfo{
					ID:    e.Peer,
					Addrs: h.Peerstore().Addrs(e.Peer),
				}:
				default:
				}
			}
		}
	}()

	sub, err := h.EventBus().Subscribe(new(event.EvtLocalAddressesUpdated))
	if err != nil {
		log.Fatal("failed to subscribe to local addresses updated event: ", err)
	}
	defer sub.Close()

	for ev := range sub.Out() {
		msg := "local addresses updated:\n"
		for _, addr := range ev.(event.EvtLocalAddressesUpdated).Current {
			msg += fmt.Sprintf("\t%s\n", addr.Address)
		}
		log.Printf(msg)
	}
}

type wrappedQUICTransport struct {
	*quic.Transport
}

func (t *wrappedQUICTransport) Listen(tlsConf *tls.Config, conf *quic.Config) (quicreuse.QUICListener, error) {
	wrappedConf := &tls.Config{
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			if slices.Contains(info.SupportedProtos, "raw") {
				cert, err := generateSelfSignedCert()
				if err != nil {
					return nil, err
				}
				return &tls.Config{
					Certificates: []tls.Certificate{*cert},
					NextProtos:   []string{"raw"},
				}, nil
			}
			fmt.Println("using original tls.Config", tlsConf.ServerName, tlsConf.GetConfigForClient != nil)
			if tlsConf.GetConfigForClient != nil {
				return tlsConf.GetConfigForClient(info)
			}
			return tlsConf, nil
		},
	}
	ln, err := t.Transport.Listen(wrappedConf, conf)
	if err != nil {
		return nil, err
	}
	return newInterceptingListener(ln, []string{"raw"}), nil
}

type interceptingListener struct {
	intercept []string

	acceptQueue chan quic.Connection
	quicreuse.QUICListener
}

func newInterceptingListener(ln quicreuse.QUICListener, intercept []string) *interceptingListener {
	return &interceptingListener{
		intercept:    intercept,
		acceptQueue:  make(chan quic.Connection, 32),
		QUICListener: ln,
	}
}

func (l *interceptingListener) Accept(ctx context.Context) (quic.Connection, error) {
start:
	conn, err := l.QUICListener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	if conn.ConnectionState().TLS.NegotiatedProtocol == "raw" {
		select {
		case l.acceptQueue <- conn:
			fmt.Println("accepted raw connection from", conn.RemoteAddr())
			goto start
		default:
			// drop connection
			conn.CloseWithError(0, "accept queue is full")
			goto start
		}
	}
	fmt.Println("returning conn to libp2p")
	return conn, nil
}

type quicAddrFilter struct{}

func (f *quicAddrFilter) filterQUICIPv4(_ peer.ID, maddrs []ma.Multiaddr) []ma.Multiaddr {
	return ma.FilterAddrs(maddrs, func(addr ma.Multiaddr) bool {
		first, _ := ma.SplitFirst(addr)
		if first == nil {
			return false
		}
		if first.Protocol().Code != ma.P_IP4 {
			return false
		}
		return isQUICAddr(addr)
	})
}

func (f *quicAddrFilter) FilterRemote(remoteID peer.ID, maddrs []ma.Multiaddr) []ma.Multiaddr {
	return f.filterQUICIPv4(remoteID, maddrs)
}

func (f *quicAddrFilter) FilterLocal(remoteID peer.ID, maddrs []ma.Multiaddr) []ma.Multiaddr {
	return f.filterQUICIPv4(remoteID, maddrs)
}

func generateSelfSignedCert() (*tls.Certificate, error) {
	// Generate a new ed25519 key pair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	// Create a certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),           // Valid from 1 hour ago
		NotAfter:     time.Now().Add(24 * time.Hour * 365), // Valid for 1 year
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	// Create the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return nil, err
	}

	// Create the tls.Certificate
	cert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	return cert, nil
}

func isQUICAddr(a ma.Multiaddr) bool {
	return mafmt.And(mafmt.IP, mafmt.Base(ma.P_UDP), mafmt.Base(ma.P_QUIC_V1)).Matches(a)
}
