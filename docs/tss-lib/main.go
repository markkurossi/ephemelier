//
// Copyright (c) 2026 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"sync"

	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
	"github.com/markkurossi/mpc/ot"
	"github.com/markkurossi/mpc/p2p"
)

var (
	bo = binary.BigEndian
)

type Peer struct {
	io      ot.IO
	PartyID *tss.PartyID
}

func NewPeer(io ot.IO, id, moniker string) (*Peer, error) {
	key, err := rand.Int(rand.Reader, big.NewInt(0).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	return &Peer{
		io:      io,
		PartyID: tss.NewPartyID(id, moniker, key),
	}, nil
}

func (peer *Peer) debugf(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	fmt.Printf("%v: %v", peer.PartyID.Id, msg)
}

func (peer *Peer) Keygen(ids tss.SortedPartyIDs) {
	ctx := tss.NewPeerContext(ids)

	partyIDMap := make(map[string]*tss.PartyID)
	for _, id := range ids {
		partyIDMap[id.Id] = id
	}

	// Keygen.
	errCh := make(chan *tss.Error)
	outCh := make(chan tss.Message)
	endCh := make(chan keygen.LocalPartySaveData)
	curve := elliptic.P256()

	params := tss.NewParameters(curve, ctx, peer.PartyID, len(ids), len(ids))
	party := keygen.NewLocalParty(params, outCh, endCh).(*keygen.LocalParty)

	go func() {
		if err := party.Start(); err != nil {
			errCh <- err
		}
	}()

	inCh := make(chan []byte)
	go func() {
		for {
			data, err := peer.io.ReceiveData()
			if err != nil {
				errCh <- party.WrapError(err)
			}
			inCh <- data
		}
	}()

	for {
		select {
		case err := <-errCh:
			log.Fatal(err)

		case msg := <-outCh:
			dst := msg.GetTo()
			peer.debugf("msg: src=%v, dst=%v\n", msg.GetFrom().Id, dst)

			if dst != nil && dst[0].Index == msg.GetFrom().Index {
				log.Fatalf("party %d tried to send a message to itself",
					dst[0].Index)
			}

			// Send message to our peer.
			data, err := marshalMessage(msg)
			if err != nil {
				log.Fatal(party.WrapError(err))
			}
			if err := peer.io.SendData(data); err != nil {
				log.Fatal(err)
			}
			if err := peer.io.Flush(); err != nil {
				log.Fatal(err)
			}

		case save := <-endCh:
			peer.debugf("save: id=%v\n", peer.PartyID.Id)
			pk := ecdsa.PublicKey{
				Curve: curve,
				X:     save.ECDSAPub.X(),
				Y:     save.ECDSAPub.Y(),
			}
			data, err := pk.Bytes()
			if err != nil {
				log.Fatalf("ecdsa.PublicKey.Bytes: %v\n", err)
			}
			peer.debugf("compressed: %x\n", data)

			data, err = json.Marshal(save)
			if err != nil {
				log.Fatalf("json.Marshal: %v\n", err)
			}
			if false {
				fmt.Printf("JSON: %v\n", string(data))
			}

			return

		case in := <-inCh:
			msg, err := unmarshalMessage(in)
			if err != nil {
				log.Fatal(err)
			}
			peer.debugf("input: src=%v\n", msg.GetFrom().Id)
			go func() {
				_, err := party.Update(msg)
				if err != nil {
					errCh <- party.WrapError(err)
				}
			}()
		}
	}
}

func main() {
	fmt.Println("TSS Main")

	tss.RegisterCurve("secp256r1", elliptic.P256())

	pG, pE := p2p.Pipe()

	e, err := NewPeer(pE, "E", "Ephemelier")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("E: Id=%v, Key=%x\n", e.PartyID.Id, e.PartyID.Key)

	g, err := NewPeer(pG, "G", "Ephemelier")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("G: Id=%v, Key=%x\n", g.PartyID.Id, g.PartyID.Key)

	ids := tss.SortPartyIDs(tss.UnSortedPartyIDs{
		e.PartyID,
		g.PartyID,
	})

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		e.Keygen(ids)
	}()
	go func() {
		defer wg.Done()
		g.Keygen(ids)
	}()

	wg.Wait()
}

func marshalMessage(msg tss.Message) ([]byte, error) {
	msgData, _, err := msg.WireBytes()
	if err != nil {
		return nil, err
	}
	fromData, err := json.Marshal(msg.GetFrom())
	if err != nil {
		return nil, err
	}

	l := 4 + len(msgData) + len(fromData) + 1

	data := make([]byte, l)
	bo.PutUint32(data, uint32(len(msgData)))
	copy(data[4:], msgData)
	copy(data[4+len(msgData):], fromData)

	if msg.IsBroadcast() {
		data[l-1] = 1
	}
	return data, nil
}

func unmarshalMessage(data []byte) (tss.ParsedMessage, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("truncated message")
	}
	msgLen := int(bo.Uint32(data))
	if 4+msgLen+1 > len(data) {
		return nil, fmt.Errorf("truncated message")
	}
	msgData := data[4 : 4+msgLen]
	fromData := data[4+msgLen : len(data)-1]
	isBroadcast := data[len(data)-1] == 1

	var from tss.PartyID
	err := json.Unmarshal(fromData, &from)
	if err != nil {
		return nil, err
	}
	return tss.ParseWireMessage(msgData, &from, isBroadcast)
}
