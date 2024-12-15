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
	"github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/event"
	"github.com/libp2p/go-libp2p/core/peer"
	libp2pquic "github.com/libp2p/go-libp2p/p2p/transport/quic"
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
	h, err := libp2p.New(
		libp2p.Transport(libp2pquic.NewTransport),
		libp2p.ListenAddrStrings("/ip4/0.0.0.0/udp/0/quic-v1"),
		libp2p.EnableHolePunching(),
	)
	if err != nil {
		return nil, err
	}
	defer h.Close()

	go func() {
		fmt.Println("subscribing to peer connectedness changed event")
		sub, err := h.EventBus().Subscribe(new(event.EvtPeerConnectednessChanged))
		if err != nil {
			log.Fatal("failed to subscribe to peer connectedness changed event: ", err)
		}
		defer sub.Close()
		for ev := range sub.Out() {
			e := ev.(event.EvtPeerConnectednessChanged)
			if e.Peer == target {
				fmt.Println("peer connectedness changed:", e.Peer, e.Connectedness)
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
			netAddr, err := manet.ToNetAddr(a)
			if err != nil {
				return nil, err
			}
			udpAddr = netAddr.(*net.UDPAddr)
		}
	}
	if udpAddr != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := quic.DialAddr(ctx, udpAddr.String(), &tls.Config{InsecureSkipVerify: true}, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to dial QUIC address: %w", err)
		}
		return conn, nil
	}

	// 2nd step: connect to the target via a relay address
	if err := h.Connect(context.Background(), ai); err != nil {
		return nil, fmt.Errorf("failed to connect to peer: %w", err)
	}
	for _, c := range h.Network().ConnsToPeer(target) {
		log.Printf("connected to %s via %s\n", c.RemotePeer(), c.RemoteMultiaddr())
	}
	select {}
}

func isQUICAddr(a ma.Multiaddr) bool {
	return mafmt.And(mafmt.IP, mafmt.Base(ma.P_UDP), mafmt.Base(ma.P_QUIC_V1)).Matches(a)
}
