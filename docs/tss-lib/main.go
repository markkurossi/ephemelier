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
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"runtime"

	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
)

type Peer struct {
	PartyID *tss.PartyID
}

func NewPeer(id, moniker string) (*Peer, error) {
	key, err := rand.Int(rand.Reader, big.NewInt(0).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	return &Peer{
		PartyID: tss.NewPartyID(id, moniker, key),
	}, nil
}

func main() {
	fmt.Println("TSS Main")

	tss.RegisterCurve("secp256r1", elliptic.P256())

	e, err := NewPeer("E", "Ephemelier")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("E: Id=%v, Key=%x\n", e.PartyID.Id, e.PartyID.Key)

	g, err := NewPeer("G", "Ephemelier")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("G: Id=%v, Key=%x\n", g.PartyID.Id, g.PartyID.Key)

	ids := tss.SortPartyIDs(tss.UnSortedPartyIDs{
		e.PartyID,
		g.PartyID,
	})
	ctx := tss.NewPeerContext(ids)

	partyIDMap := make(map[string]*tss.PartyID)
	for _, id := range ids {
		partyIDMap[id.Id] = id
	}

	// Keygen.
	errCh := make(chan *tss.Error)
	outCh := make(chan tss.Message)
	endCh := make(chan keygen.LocalPartySaveData)

	var parties []*keygen.LocalParty

	curve := elliptic.P256()

	for _, id := range ids {
		params := tss.NewParameters(curve, ctx, id, len(ids), len(ids))
		p := keygen.NewLocalParty(params, outCh, endCh).(*keygen.LocalParty)
		parties = append(parties, p)
		go func(p *keygen.LocalParty) {
			if err := p.Start(); err != nil {
				errCh <- err
			}
		}(p)
	}

	var done int
keygen:
	for {
		fmt.Printf("Active goroutines: %d\n", runtime.NumGoroutine())
		select {
		case err := <-errCh:
			fmt.Printf("err: %v\n", err)
			os.Exit(1)

		case msg := <-outCh:
			dst := msg.GetTo()
			if dst == nil {
				// Broadcast.
				for _, p := range parties {
					if p.PartyID().Index != msg.GetFrom().Index {
						go updater(p, msg, errCh)
					}
				}
			} else {
				// Point-to-point.
				go updater(parties[dst[0].Index], msg, errCh)
			}

		case save := <-endCh:
			fmt.Printf("save: %v\n", save)
			data, err := json.Marshal(save)
			if err != nil {
				log.Fatalf("json.Marshal: %v\n", err)
			}
			fmt.Printf("JSON: %v\n", string(data))

			pk := ecdsa.PublicKey{
				Curve: curve,
				X:     save.ECDSAPub.X(),
				Y:     save.ECDSAPub.Y(),
			}
			data, err = pk.Bytes()
			if err != nil {
				log.Fatalf("ecdsa.PublicKey.Bytes: %v\n", err)
			}
			fmt.Printf("compressed: %x\n", data)

			done++
			if done == len(ids) {
				fmt.Printf("Received save data from %d participants\n", done)
				break keygen
			}
		}
	}
}

func updater(party tss.Party, msg tss.Message, errCh chan<- *tss.Error) {
	// do not send a message from this party back to itself
	if party.PartyID() == msg.GetFrom() {
		return
	}
	bz, _, err := msg.WireBytes()
	if err != nil {
		errCh <- party.WrapError(err)
		return
	}
	pMsg, err := tss.ParseWireMessage(bz, msg.GetFrom(), msg.IsBroadcast())
	if err != nil {
		errCh <- party.WrapError(err)
		return
	}
	if _, err := party.Update(pMsg); err != nil {
		errCh <- err
	}
}
