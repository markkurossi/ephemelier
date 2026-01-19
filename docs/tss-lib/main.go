//
// Copyright (c) 2026 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"sync"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/markkurossi/mpc/ot"
	"github.com/markkurossi/mpc/p2p"
)

var (
	bo = binary.BigEndian
)

type Peer struct {
	io      ot.IO
	ctx     *tss.PeerContext
	PartyID *tss.PartyID
}

func makePartyID(id string) *tss.PartyID {
	var keyData []byte
	const moniker = "Ephemelier"

	keyData = append(keyData, []byte(id)...)
	keyData = append(keyData, []byte(moniker)...)

	key := new(big.Int).SetBytes(keyData)

	return tss.NewPartyID(id, moniker, key)
}

func NewPeer(io ot.IO, evaluator bool) (*Peer, error) {
	ids := tss.SortPartyIDs(tss.UnSortedPartyIDs{
		makePartyID("E"),
		makePartyID("G"),
	})

	var this string
	if evaluator {
		this = "E"
	} else {
		this = "G"
	}

	var id *tss.PartyID
	for _, i := range ids {
		if i.Id == this {
			id = i
		}
	}

	return &Peer{
		io:      io,
		ctx:     tss.NewPeerContext(ids),
		PartyID: id,
	}, nil
}

func (peer *Peer) debugf(format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	fmt.Printf("%v: %v", peer.PartyID.Id, msg)
}

// Keygen implements the threshold key generation.
func (peer *Peer) Keygen() {
	errCh := make(chan *tss.Error)
	outCh := make(chan tss.Message)
	endCh := make(chan *keygen.LocalPartySaveData)
	curve := elliptic.P256()

	n := len(peer.ctx.IDs())

	params := tss.NewParameters(curve, peer.ctx, peer.PartyID, n, 1)
	party := keygen.NewLocalParty(params, outCh, endCh).(*keygen.LocalParty)

	go func() {
		if err := party.Start(); err != nil {
			errCh <- err
		}
	}()

	inCh := make(chan []byte)
	go func() {
		for { // XXX when to terminate
			data, err := peer.io.ReceiveData()
			if err != nil {
				errCh <- party.WrapError(err)
				return
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

			err = peer.writeSaveData(save)
			if err != nil {
				log.Fatal(err)
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

func (peer *Peer) Sign(msg []byte) {
	errCh := make(chan *tss.Error)
	outCh := make(chan tss.Message)
	endCh := make(chan *common.SignatureData)
	curve := elliptic.P256()

	n := len(peer.ctx.IDs())

	key, err := peer.loadSaveData()
	if err != nil {
		log.Fatal(err)
	}

	peer.debugf("n=%v\n", n)
	peer.debugf("ids=%v\n", peer.ctx.IDs())

	params := tss.NewParameters(curve, peer.ctx, peer.PartyID, n, 1)
	party := signing.NewLocalParty(new(big.Int).SetBytes(msg), params, key,
		outCh, endCh, len(msg)).(*signing.LocalParty)

	go func() {
		if err := party.Start(); err != nil {
			errCh <- err
		}
	}()

	inCh := make(chan []byte)
	go func() {
		for { // XXX when to terminate
			data, err := peer.io.ReceiveData()
			if err != nil {
				errCh <- party.WrapError(err)
				return
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

		case signature := <-endCh:
			peer.debugf("signature: %x\n", signature.Signature)

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
	flag.Parse()
	if len(flag.Args()) != 1 {
		log.Fatalf("usage: tss-lib keygen/sign\n")
	}

	tss.RegisterCurve("secp256r1", elliptic.P256())

	pG, pE := p2p.Pipe()

	e, err := NewPeer(pE, true)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("E: Id=%v, Key=%x\n", e.PartyID.Id, e.PartyID.Key)

	g, err := NewPeer(pG, false)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("G: Id=%v, Key=%x\n", g.PartyID.Id, g.PartyID.Key)

	var wg sync.WaitGroup
	wg.Add(2)

	switch flag.Args()[0] {
	case "keygen":
		go func() {
			defer wg.Done()
			e.Keygen()
		}()
		go func() {
			defer wg.Done()
			g.Keygen()
		}()

	case "sign":
		msg := []byte("Hello, world!")

		go func() {
			defer wg.Done()
			e.Sign(msg)
		}()
		go func() {
			defer wg.Done()
			g.Sign(msg)
		}()

	default:
		log.Fatalf("invalid operation: %v\n", flag.Args()[0])
	}

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

func (peer *Peer) writeSaveData(save *keygen.LocalPartySaveData) error {
	data, err := json.Marshal(save)
	if err != nil {
		return err
	}
	f, err := os.Create(fmt.Sprintf("peer-%v.share", peer.PartyID.Id))
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(data)
	return err
}

func (peer *Peer) loadSaveData() (keygen.LocalPartySaveData, error) {
	var result keygen.LocalPartySaveData

	f, err := os.Open(fmt.Sprintf("peer-%v.share", peer.PartyID.Id))
	if err != nil {
		return result, err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return result, err
	}
	err = json.Unmarshal(data, &result)
	return result, err
}
