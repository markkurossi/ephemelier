//
// Copyright (c) 2026 Markku Rossi
//
// All rights reserved.
//

// Package tss implements multi-party threshold signature scheme using
// the https://github.com/bnb-chain/tss-lib library.
package tss

import (
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"

	"github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/markkurossi/mpc/ot"
)

var (
	bo = binary.BigEndian
)

// Peer implements a two-party peer for threshold signature scheme.
type Peer struct {
	io      ot.IO
	ctx     *tss.PeerContext
	PartyID *tss.PartyID
}

func init() {
	tss.RegisterCurve("secp256r1", elliptic.P256())
}

func makePartyID(id string) *tss.PartyID {
	var keyData []byte
	const moniker = "Ephemelier"

	keyData = append(keyData, []byte(id)...)
	keyData = append(keyData, []byte(moniker)...)

	key := new(big.Int).SetBytes(keyData)

	return tss.NewPartyID(id, moniker, key)
}

// NewPeer creates a new two-party peer for threshold signature
// scheme. The argument specifies the peer's ID (evaluator / garbler).
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
func (peer *Peer) Keygen() (*keygen.LocalPartySaveData, error) {
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
			return nil, err

		case msg := <-outCh:
			dst := msg.GetTo()
			peer.debugf("msg: src=%v, dst=%v\n", msg.GetFrom().Id, dst)

			if dst != nil && dst[0].Index == msg.GetFrom().Index {
				return nil, fmt.Errorf("party %v sending a message to itself",
					peer.PartyID)
			}

			// Send message to our peer.
			data, err := marshalMessage(msg)
			if err != nil {
				return nil, party.WrapError(err)
			}
			if err := peer.io.SendData(data); err != nil {
				return nil, party.WrapError(err)
			}
			if err := peer.io.Flush(); err != nil {
				return nil, party.WrapError(err)
			}

		case save := <-endCh:
			peer.debugf("save: id=%v\n", peer.PartyID.Id)
			pk := save.ECDSAPub.ToECDSAPubKey()
			data, err := pk.Bytes()
			if err != nil {
				return nil, err
			}
			peer.debugf("compressed: %x\n", data)

			return save, nil

		case in := <-inCh:
			msg, err := unmarshalMessage(in)
			if err != nil {
				return nil, err
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

// Sign implements the threshold signature for the message msg using
// the local key share key. The function returns the message hash,
// signature, and an optional error.
func (peer *Peer) Sign(key *keygen.LocalPartySaveData, msg []byte) (
	[]byte, []byte, error) {

	errCh := make(chan *tss.Error)
	outCh := make(chan tss.Message)
	endCh := make(chan *common.SignatureData)
	curve := elliptic.P256()

	n := len(peer.ctx.IDs())

	params := tss.NewParameters(curve, peer.ctx, peer.PartyID, n, 1)
	party := signing.NewLocalParty(new(big.Int).SetBytes(msg), params, *key,
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
			return nil, nil, err

		case msg := <-outCh:
			dst := msg.GetTo()
			peer.debugf("msg: src=%v, dst=%v\n", msg.GetFrom().Id, dst)

			if dst != nil && dst[0].Index == msg.GetFrom().Index {
				return nil, nil,
					fmt.Errorf("party %v sending a message to itself",
						peer.PartyID)
			}

			// Send message to our peer.
			data, err := marshalMessage(msg)
			if err != nil {
				return nil, nil, party.WrapError(err)
			}
			if err := peer.io.SendData(data); err != nil {
				return nil, nil, err
			}
			if err := peer.io.Flush(); err != nil {
				return nil, nil, err
			}

		case signature := <-endCh:
			peer.debugf("signature: %x\n", signature.Signature)

			sig := ecdsaSig{
				R: new(big.Int).SetBytes(signature.R),
				S: new(big.Int).SetBytes(signature.S),
			}

			data, err := asn1.Marshal(sig)
			if err != nil {
				return nil, nil, err
			}
			return signature.M, data, nil

		case in := <-inCh:
			msg, err := unmarshalMessage(in)
			if err != nil {
				return nil, nil, err
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

type ecdsaSig struct {
	R *big.Int
	S *big.Int
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

// WriteSaveData writes the local party save data to file.
func WriteSaveData(file string, save *keygen.LocalPartySaveData) error {
	data, err := json.Marshal(save)
	if err != nil {
		return err
	}
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(data)
	return err
}

// ReadSaveData reads the local party save data from file.
func ReadSaveData(file string) (*keygen.LocalPartySaveData, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	result := new(keygen.LocalPartySaveData)
	err = json.Unmarshal(data, result)
	if err != nil {
		return nil, err
	}
	return result, nil
}
