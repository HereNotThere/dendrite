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
	"net/http"
	"strings"
	"testing"

	"github.com/matrix-org/dendrite/setup/config"
	uapi "github.com/matrix-org/dendrite/userapi/api"
	"github.com/stretchr/testify/assert"
)

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

func TLoginPublicKeyNewSession(t *testing.T) {
	// Setup
	var userAPI fakePublicKeyUserApi
	ctx := context.Background()
	cfg := initializeTestConfig()
	userInteractive := initializeTestUserInteractive()

	test := struct {
		Body string
	}{
		Body: `{ "type": "m.login.publickey" }`,
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
	assert.NotNilf(err, "Failed: %+v", login)
	assert.Truef(
		err.Code == http.StatusUnauthorized,
		"err.Code: got %v, want %v", err.Code, http.StatusUnauthorized)
	json := err.JSON.(Challenge)
	assert.Emptyf(json.Completed, "Challenge.Completed array")
	assert.Emptyf(json.Flows, "Challenge.Flows array")
	assert.Emptyf(json.Params, "Challenge.Params array")
	assert.NotEmptyf(json.Session, "Challenge.Session")
}

func TLoginPublicKeyInvalidSessionId(t *testing.T) {
	// Setup
	var userAPI fakePublicKeyUserApi
	ctx := context.Background()
	cfg := initializeTestConfig()
	userInteractive := initializeTestUserInteractive()

	test := struct {
		Body string
	}{
		Body: `{
			"type": "m.login.publickey",
			"auth": {
				"type": "m.login.publickey.ethereum",
				"session": "invalid_session_id"
			}
		 }`,
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
		"err.Code: actual %v, expected %v", err.Code, http.StatusUnauthorized)
}

func TLoginPublicKeyInvalidAuthType(t *testing.T) {
	// Setup
	var userAPI fakePublicKeyUserApi
	ctx := context.Background()
	cfg := initializeTestConfig()
	userInteractive := initializeTestUserInteractive()

	test := struct {
		Body string
	}{
		Body: `{
			"type": "m.login.publickey",
			"auth": {
				"type": "m.login.publickey.someAlgo"
			}
		 }`,
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
	assert.NotNil(err, "Expected an err response. Actual: nil")
	assert.Truef(
		err.Code == http.StatusUnauthorized,
		"err.Code: actual %v, expected %v", err.Code, http.StatusUnauthorized)
	_, ok := err.JSON.(Challenge)
	assert.False(
		ok,
		"should not return a Challenge response",
	)
}
