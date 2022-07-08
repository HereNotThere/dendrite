// Copyright 2022 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"net/http"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"
)

type EthereumWallet struct {
	Address    string
	PrivateKey *ecdsa.PrivateKey
}

// https://goethereumbook.org/wallet-generate/
func createAccount() *EthereumWallet {
	// Create a new public / private key pair.
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	// Get the public key
	publicKey := privateKey.Public()

	// Transform public key to the Ethereum address
	publicKeyEcdsa, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("error casting public key to ECDSA")
	}

	address := crypto.PubkeyToAddress(*publicKeyEcdsa).Hex()

	return &EthereumWallet{
		Address:    address,
		PrivateKey: privateKey,
	}
}

func This(t *testing.T) {

}

func TestLoginPublicKeyEthereumInvalidUserId(t *testing.T) {
	// Setup
	var userAPI fakePublicKeyUserApi
	ctx := context.Background()
	cfg := initializeConfigClientApi()
	userInteractive := initializeUserInteractive()
	wallet := createAccount()
	sessionId := testPublicKeySession(
		&ctx,
		cfg,
		userInteractive,
		&userAPI,
	)

	body := fmt.Sprintf(`{
		"type": "m.login.publickey",
		"auth": {
			"type": "m.login.publickey.ethereum",
			"session": "%v",
			"user_id": "%v"
		}
	 }`, sessionId, wallet.Address)
	test := struct {
		Body string
	}{
		Body: body,
	}

	// Test
	_, cleanup, err := LoginFromJSONReader(
		ctx,
		strings.NewReader(test.Body),
		&userAPI,
		&userAPI,
		&userAPI,
		userInteractive,
		cfg)

	if cleanup != nil {
		cleanup(ctx, nil)
	}

	// Asserts
	assert := assert.New(t)
	assert.Truef(
		err.Code == http.StatusForbidden,
		"err.Code: got %v, want %v", err.Code, http.StatusForbidden)
}

func LoginPublicKeyEthereumMissingUserId(t *testing.T) {
	// Setup
	var userAPI fakePublicKeyUserApi
	ctx := context.Background()
	cfg := initializeConfigClientApi()
	userInteractive := initializeUserInteractive()
	sessionId := testPublicKeySession(
		&ctx,
		cfg,
		userInteractive,
		&userAPI,
	)

	body := fmt.Sprintf(`{
		"type": "m.login.publickey",
		"auth": {
			"type": "m.login.publickey.ethereum",
			"session": "%v"
		}
	 }`, sessionId)
	test := struct {
		Body string
	}{
		Body: body,
	}

	// Test
	_, cleanup, err := LoginFromJSONReader(
		ctx,
		strings.NewReader(test.Body),
		&userAPI,
		&userAPI,
		&userAPI,
		userInteractive,
		cfg)

	if cleanup != nil {
		cleanup(ctx, nil)
	}

	// Asserts
	assert := assert.New(t)
	assert.Truef(
		err.Code == http.StatusForbidden,
		"err.Code: got %v, want %v", err.Code, http.StatusForbidden)
}

func LoginPublicKeyEthereumAccountNotAvailable(t *testing.T) {
	// Setup
	var userAPI fakePublicKeyUserApi
	ctx := context.Background()
	cfg := initializeConfigClientApi()
	userInteractive := initializeUserInteractive()
	sessionId := testPublicKeySession(
		&ctx,
		cfg,
		userInteractive,
		&userAPI,
	)

	body := fmt.Sprintf(`{
		"type": "m.login.publickey",
		"auth": {
			"type": "m.login.publickey.ethereum",
			"session": "%v",
			"user_id": "does_not_exist"
		}
	 }`, sessionId)
	test := struct {
		Body string
	}{
		Body: body,
	}

	// Test
	_, cleanup, err := LoginFromJSONReader(
		ctx,
		strings.NewReader(test.Body),
		&userAPI,
		&userAPI,
		&userAPI,
		userInteractive,
		cfg)

	if cleanup != nil {
		cleanup(ctx, nil)
	}

	// Asserts
	assert := assert.New(t)
	assert.Truef(
		err.Code == http.StatusForbidden,
		"err.Code: got %v, want %v", err.Code, http.StatusForbidden)
}
