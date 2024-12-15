package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	libp2pquic "github.com/libp2p/go-libp2p/p2p/transport/quic"
	"github.com/libp2p/go-libp2p/p2p/transport/quicreuse"
	ma "github.com/multiformats/go-multiaddr"
	mafmt "github.com/multiformats/go-multiaddr-fmt"
	manet "github.com/multiformats/go-multiaddr/net"
	"github.com/quic-go/quic-go"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: client <peer-id>")
	}
	id, err := peer.Decode(os.Args[1])
	if err != nil {
		log.Fatal("failed to decode peer ID: ", err)
	}
	conn, err := runClient(id)
	if err != nil {
		log.Fatal("failed to run client: ", err)
	}
	defer conn.CloseWithError(quic.ApplicationErrorCode(42), "no error")
	fmt.Println("obtained a direct QUIC connection to", conn.RemoteAddr())
}

func runClient(target peer.ID) (quic.Connection, error) {
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP listener: %w", err)
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
	h, err := libp2p.New(
		libp2p.Transport(libp2pquic.NewTransport),
		libp2p.ListenAddrStrings(fmt.Sprintf("/ip4/0.0.0.0/udp/%d/quic-v1", udpConn.LocalAddr().(*net.UDPAddr).Port)),
		libp2p.EnableHolePunching(),
		libp2p.QUICReuse(newReuse),
	)
	if err != nil {
		return nil, err
	}
	defer h.Close()
	log.Println("I am:", h.ID())

	connected := make(chan struct{}, 1)
	go func() {
		sub, err := h.EventBus().Subscribe(new(event.EvtPeerConnectednessChanged))
		if err != nil {
			log.Fatal("failed to subscribe to peer connectedness changed event: ", err)
		}
		defer sub.Close()
		for ev := range sub.Out() {
			e := ev.(event.EvtPeerConnectednessChanged)
			if e.Peer == target {
				msg := fmt.Sprintf("peer connectedness changed: %s\n", e.Connectedness)
				for _, c := range h.Network().ConnsToPeer(target) {
					msg += fmt.Sprintf("\t%s <-> %s\n", c.LocalMultiaddr(), c.RemoteMultiaddr())
				}
				log.Println(msg)
				if e.Connectedness == network.Connected {
					connected <- struct{}{}
				}
			}
		}
	}()

	ipfsDHT, err := dht.New(
		context.Background(),
		h,
		dht.Mode(dht.ModeClient),
		dht.BootstrapPeers(dht.GetDefaultBootstrapPeerAddrInfos()...),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create DHT: %w", err)
	}
	defer ipfsDHT.Close()
	if err := ipfsDHT.Bootstrap(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to bootstrap DHT: %w", err)
	}

	// give the DHT some time to boot up,
	// and Identify to discover our public addresses
	time.Sleep(5 * time.Second)

	ai, err := ipfsDHT.FindPeer(context.Background(), target)
	if err != nil {
		return nil, fmt.Errorf("failed to find peer: %w", err)
	}
	msg := fmt.Sprintf("found addresses for peer %s:\n", target)
	for _, a := range ai.Addrs {
		msg += fmt.Sprintf("\t%s\n", a)
	}
	log.Println(msg)
	h.Peerstore().AddAddrs(target, ai.Addrs, time.Hour)

	// 1st step: check we have a public QUIC address for the target
	var udpAddr *net.UDPAddr
	for _, a := range h.Peerstore().Addrs(target) {
		if manet.IsPublicAddr(a) && isQUICAddr(a) {
			udpAddr, err = quicAddrToNetAddr(a)
			if err != nil {
				return nil, fmt.Errorf("failed to convert multiaddr to net.UDPAddr: %w", err)
			}
			break
		}
	}
	if udpAddr != nil {
		return dialQUIC(tr, udpAddr)
	}

	// 2nd step: connect to the target via a relay address
	if err := h.Connect(context.Background(), ai); err != nil {
		return nil, fmt.Errorf("failed to connect to peer: %w", err)
	}

	select {
	case <-connected:
	case <-time.After(5 * time.Second):
		return nil, fmt.Errorf("timed out waiting for direct (e.g. hole-punched) connection")
	}

	var directAddr *net.UDPAddr
	for _, c := range h.Network().ConnsToPeer(target) {
		if a := c.RemoteMultiaddr(); isQUICAddr(a) {
			directAddr, err = quicAddrToNetAddr(a)
			if err != nil {
				return nil, fmt.Errorf("failed to convert multiaddr to net.UDPAddr: %w", err)
			}
			break
		}
	}
	if directAddr == nil {
		return nil, fmt.Errorf("failed to find a direct QUIC address for peer %s after hole punching", target)
	}
	log.Printf("dialing QUIC address: %s", directAddr)
	return dialQUIC(tr, directAddr)
}

func dialQUIC(tr *quic.Transport, addr *net.UDPAddr) (quic.Connection, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := tr.Dial(
		ctx,
		addr,
		&tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"raw"},
		},
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to dial QUIC address: %w", err)
	}
	return conn, nil
}

func isQUICAddr(a ma.Multiaddr) bool {
	return mafmt.And(mafmt.IP, mafmt.Base(ma.P_UDP), mafmt.Base(ma.P_QUIC_V1)).Matches(a)
}

func quicAddrToNetAddr(a ma.Multiaddr) (*net.UDPAddr, error) {
	first, _ := ma.SplitFunc(a, func(c ma.Component) bool { return c.Protocol().Code == ma.P_QUIC_V1 })
	if first == nil {
		return nil, fmt.Errorf("no QUIC address found in multiaddr")
	}
	netAddr, err := manet.ToNetAddr(first)
	if err != nil {
		return nil, fmt.Errorf("failed to convert multiaddr to net.Addr: %w", err)
	}
	return netAddr.(*net.UDPAddr), nil
}

type wrappedQUICTransport struct {
	*quic.Transport
}

func (t *wrappedQUICTransport) Listen(tlsConf *tls.Config, conf *quic.Config) (quicreuse.QUICListener, error) {
	return t.Transport.Listen(tlsConf, conf)
}
