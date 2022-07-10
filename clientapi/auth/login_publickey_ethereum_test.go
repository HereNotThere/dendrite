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

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/matrix-org/dendrite/clientapi/jsonerror"
	"github.com/spruceid/siwe-go"
	"github.com/stretchr/testify/assert"
)

const testNetworkId = 4 // Rinkeby test network ID

type ethereumTestWallet struct {
	Eip155UserId  string
	PublicAddress string
	PrivateKey    *ecdsa.PrivateKey
}

// https://goethereumbook.org/wallet-generate/
func createTestAccount() *ethereumTestWallet {
	// Create a new public / private key pair.
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
		return nil
	}

	// Get the public key
	publicKey := privateKey.Public()

	// Transform public key to the Ethereum address
	publicKeyEcdsa, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("error casting public key to ECDSA")
		return nil
	}

	address := crypto.PubkeyToAddress(*publicKeyEcdsa).Hex()
	eip155UserId := fmt.Sprintf("eip155=3a%d=3a%s", testNetworkId, address)

	return &ethereumTestWallet{
		PublicAddress: address,
		PrivateKey:    privateKey,
		Eip155UserId:  eip155UserId,
	}
}

func createEip4361TestMessage(
	publicAddress string,
) *siwe.Message {
	options := make(map[string]interface{})
	options["chainId"] = 4 // Rinkeby test network
	options["statement"] = "This is a test statement"
	message, err := siwe.InitMessage(
		"example.com",
		publicAddress,
		"https://localhost/login",
		siwe.GenerateNonce(),
		options,
	)

	if err != nil {
		log.Fatal(err)
		return nil
	}

	return message
}

func fromMessageToString(message *siwe.Message) string {
	// Escape the formatting characters to
	// prevent unmarshall exceptions.
	str := strings.ReplaceAll(message.String(), "\n", "\\n")
	str = strings.ReplaceAll(str, "\t", "\\t")
	return str
}

// https://goethereumbook.org/signature-generate/
func signMessage(message string, privateKey *ecdsa.PrivateKey) string {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
	data := []byte(msg)
	hash := crypto.Keccak256Hash(data)

	signature, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		log.Fatal(err)
		return ""
	}

	// https://github.com/ethereum/go-ethereum/blob/55599ee95d4151a2502465e0afc7c47bd1acba77/internal/ethapi/api.go#L442
	signature[64] += 27 // Transform V from 0/1 to 27/28 according to the yellow paper
	return hexutil.Encode(signature)
}

func TestLoginPublicKeyEthereum(t *testing.T) {
	// Setup
	var userAPI fakePublicKeyUserApi
	ctx := context.Background()
	cfg := initializeTestConfig()
	userInteractive := initializeTestUserInteractive()
	wallet := createTestAccount()
	message := createEip4361TestMessage(wallet.PublicAddress)
	signature := signMessage(message.String(), wallet.PrivateKey)
	sessionId := testPublicKeySession(
		&ctx,
		cfg,
		userInteractive,
		&userAPI,
	)

	// Escape \t and \n. Work around for marshalling and unmarshalling message.
	msgStr := fromMessageToString(message)
	body := fmt.Sprintf(`{
		"type": "m.login.publickey",
		"auth": {
			"type": "m.login.publickey.ethereum",
			"session": "%v",
			"user_id": "%v",
			"message": "%v",
			"signature": "%v"
		}
	 }`,
		sessionId,
		wallet.Eip155UserId,
		msgStr,
		signature,
	)
	test := struct {
		Body string
	}{
		Body: body,
	}

	// Test
	login, cleanup, err := LoginFromJSONReader(
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
	assert.Nilf(err, "err: actual: %v, expected: nil", err)
	assert.NotNil(login, "login: actual: nil, expected: not nil nil")
	assert.Truef(
		login.Identifier.Type == "m.id.decentralizedid",
		"login.Identifier.Type actual:  %v, expected:  %v", login.Identifier.Type, "m.id.decentralizedid")
	walletAddress := strings.ToLower(wallet.Eip155UserId)
	assert.Truef(
		login.Identifier.User == walletAddress,
		"login.Identifier.User actual:  %v, expected:  %v", login.Identifier.User, walletAddress)
}

func TestLoginPublicKeyEthereumMissingSignature(t *testing.T) {
	// Setup
	var userAPI fakePublicKeyUserApi
	ctx := context.Background()
	cfg := initializeTestConfig()
	userInteractive := initializeTestUserInteractive()
	wallet := createTestAccount()
	message := createEip4361TestMessage(wallet.PublicAddress)
	sessionId := testPublicKeySession(
		&ctx,
		cfg,
		userInteractive,
		&userAPI,
	)

	// Escape \t and \n. Work around for marshalling and unmarshalling message.
	msgStr := fromMessageToString(message)
	body := fmt.Sprintf(`{
		"type": "m.login.publickey",
		"auth": {
			"type": "m.login.publickey.ethereum",
			"session": "%v",
			"user_id": "%v",
			"message": "%v"
		}
	 }`,
		sessionId,
		wallet.Eip155UserId,
		msgStr,
	)
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
		err.Code == http.StatusUnauthorized,
		"err.Code actual: %v, expected:  %v", err.Code, http.StatusUnauthorized)
	json := err.JSON.(*jsonerror.MatrixError)
	expectedErr := jsonerror.InvalidSignature("")
	assert.Truef(
		json.ErrCode == expectedErr.ErrCode,
		"err.JSON.ErrCode actual: %v, expected: %v", json.ErrCode, expectedErr.ErrCode)
}

func TestLoginPublicKeyEthereumEmptyMessage(t *testing.T) {
	// Setup
	var userAPI fakePublicKeyUserApi
	ctx := context.Background()
	cfg := initializeTestConfig()
	userInteractive := initializeTestUserInteractive()
	wallet := createTestAccount()
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
	 }`, sessionId, wallet.Eip155UserId)
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
		err.Code == http.StatusUnauthorized,
		"err.Code actual: %v, expected: %v", err.Code, http.StatusUnauthorized)
	json := err.JSON.(*jsonerror.MatrixError)
	expectedErr := jsonerror.InvalidParam("")
	assert.Truef(
		json.ErrCode == expectedErr.ErrCode,
		"err.JSON.ErrCode actual: %v, expected: %v", json.ErrCode, expectedErr.ErrCode)
}

func TestLoginPublicKeyEthereumWrongUserId(t *testing.T) {
	// Setup
	var userAPI fakePublicKeyUserApi
	ctx := context.Background()
	cfg := initializeTestConfig()
	userInteractive := initializeTestUserInteractive()
	wallet := createTestAccount()
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
	 }`, sessionId, wallet.PublicAddress)
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
		"err.Code actual: %v, expected: %v", err.Code, http.StatusForbidden)
}

func TestLoginPublicKeyEthereumMissingUserId(t *testing.T) {
	// Setup
	var userAPI fakePublicKeyUserApi
	ctx := context.Background()
	cfg := initializeTestConfig()
	userInteractive := initializeTestUserInteractive()
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
		"err.Code actual: %v, expected: %v", err.Code, http.StatusForbidden)
}

func TestLoginPublicKeyEthereumAccountNotAvailable(t *testing.T) {
	// Setup
	var userAPI fakePublicKeyUserApi
	ctx := context.Background()
	cfg := initializeTestConfig()
	userInteractive := initializeTestUserInteractive()
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
		"err.Code actual: %v, expected: %v", err.Code, http.StatusForbidden)
}
