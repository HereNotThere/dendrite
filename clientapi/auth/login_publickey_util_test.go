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

/**
Test utilities for publickey login and registration.
No tests in this file.
*/

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"strings"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/matrix-org/dendrite/setup/config"
	uapi "github.com/matrix-org/dendrite/userapi/api"
	"github.com/spruceid/siwe-go"
)

const testNetworkId = 4 // Rinkeby test network ID

type fakePublicKeyUserApi struct {
	UserInternalAPIForLogin
	uapi.UserLoginAPI
	uapi.ClientUserAPI
	DeletedTokens []string
}

func (ua *fakePublicKeyUserApi) QueryAccountAvailability(ctx context.Context, req *uapi.QueryAccountAvailabilityRequest, res *uapi.QueryAccountAvailabilityResponse) error {
	if req.Localpart == "does_not_exist" {
		res.Available = true
		return nil
	}

	res.Available = false
	return nil
}

func (ua *fakePublicKeyUserApi) QueryAccountByPassword(ctx context.Context, req *uapi.QueryAccountByPasswordRequest, res *uapi.QueryAccountByPasswordResponse) error {
	if req.PlaintextPassword == "invalidpassword" {
		res.Account = nil
		return nil
	}
	res.Exists = true
	res.Account = &uapi.Account{}
	return nil
}

func (ua *fakePublicKeyUserApi) PerformLoginTokenDeletion(ctx context.Context, req *uapi.PerformLoginTokenDeletionRequest, res *uapi.PerformLoginTokenDeletionResponse) error {
	ua.DeletedTokens = append(ua.DeletedTokens, req.Token)
	return nil
}

func (ua *fakePublicKeyUserApi) PerformLoginTokenCreation(ctx context.Context, req *uapi.PerformLoginTokenCreationRequest, res *uapi.PerformLoginTokenCreationResponse) error {
	return nil
}

func (*fakePublicKeyUserApi) QueryLoginToken(ctx context.Context, req *uapi.QueryLoginTokenRequest, res *uapi.QueryLoginTokenResponse) error {
	if req.Token == "invalidtoken" {
		return nil
	}

	res.Data = &uapi.LoginTokenData{UserID: "@auser:example.com"}
	return nil
}

func initializeTestUserInteractive() *UserInteractive {
	userInteractive := UserInteractive{
		Flows:    []userInteractiveFlow{},
		Types:    make(map[string]Type),
		Sessions: make(map[string][]string),
		Params:   make(map[string]interface{}),
	}

	return &userInteractive
}

func initializeTestConfig() *config.ClientAPI {
	chainIds := []int{4}
	cfg := &config.ClientAPI{
		Matrix: &config.Global{
			ServerName: serverName,
		},
		PublicKeyAuthentication: config.PublicKeyAuthentication{
			Ethereum: config.EthereumAuthConfig{
				Enabled:  true,
				Version:  1,
				ChainIDs: chainIds,
			},
		},
	}

	return cfg
}

func testPublicKeySession(
	ctx *context.Context,
	cfg *config.ClientAPI,
	userInteractive *UserInteractive,
	userAPI *fakePublicKeyUserApi,

) string {
	emptyAuth := struct {
		Body string
	}{
		Body: `{
			"type": "m.login.publickey"
		 }`,
	}

	_, cleanup, err := LoginFromJSONReader(
		*ctx,
		strings.NewReader(emptyAuth.Body),
		userAPI,
		userAPI,
		userAPI,
		userInteractive,
		cfg)

	if cleanup != nil {
		cleanup(*ctx, nil)
	}

	json := err.JSON.(Challenge)
	return json.Session
}

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
	// prevent unmarshal exceptions.
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
