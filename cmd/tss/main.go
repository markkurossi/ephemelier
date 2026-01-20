//
// Copyright (c) 2026 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"crypto/ecdsa"
	"flag"
	"fmt"
	"log"
	"sync"

	"github.com/markkurossi/ephemelier/crypto/tss"
	"github.com/markkurossi/mpc/p2p"
)

func main() {
	flag.Parse()
	if len(flag.Args()) != 1 {
		log.Fatalf("usage: tss keygen/sign\n")
	}

	pG, pE := p2p.Pipe()

	e, err := tss.NewPeer(pE, true)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("E: Id=%v, Key=%x\n", e.PartyID.Id, e.PartyID.Key)

	g, err := tss.NewPeer(pG, false)
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
			save, err := e.Keygen()
			if err != nil {
				log.Fatal(err)
			}
			err = tss.WriteSaveData(shareName(e), save)
			if err != nil {
				log.Fatal(err)
			}
		}()
		go func() {
			defer wg.Done()
			save, err := g.Keygen()
			if err != nil {
				log.Fatal(err)
			}
			err = tss.WriteSaveData(shareName(g), save)
			if err != nil {
				log.Fatal(err)
			}
		}()

	case "sign":
		msg := []byte("Hello, world!")

		go func() {
			defer wg.Done()
			key, err := tss.ReadSaveData(shareName(e))
			if err != nil {
				log.Fatal(err)
			}
			hash, signature, err := e.Sign(key, msg)
			if err != nil {
				log.Fatal(err)
			}
			verifySignature(key.ECDSAPub.ToECDSAPubKey(), hash, signature)
		}()
		go func() {
			defer wg.Done()
			key, err := tss.ReadSaveData(shareName(g))
			if err != nil {
				log.Fatal(err)
			}
			hash, signature, err := g.Sign(key, msg)
			if err != nil {
				log.Fatal(err)
			}
			verifySignature(key.ECDSAPub.ToECDSAPubKey(), hash, signature)
		}()

	default:
		log.Fatalf("invalid operation: %v\n", flag.Args()[0])
	}

	wg.Wait()
}

func shareName(peer *tss.Peer) string {
	return fmt.Sprintf("peer-%v.share", peer.PartyID.Id)
}

func verifySignature(key *ecdsa.PublicKey, hash, signature []byte) {
	fmt.Printf("verifySignature:\n")
	keyBytes, err := key.Bytes()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf(" pubkey: %x\n", keyBytes)
	result := ecdsa.VerifyASN1(key, hash, signature)
	fmt.Printf(" verify: %v\n", result)
}
