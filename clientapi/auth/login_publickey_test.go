// Copyright 2021 The Matrix.org Foundation C.I.C.
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

func TestLoginPublicKeyNewSession(t *testing.T) {
	assert := assert.New(t)
	ctx := context.Background()

	test := struct {
		Name string
		Body string

		WantUsername string
	}{
		Name: "TestLoginPublicKeyNewSession",
		Body: `{ "type": "m.login.publickey" }`,
	}

	cfg := initializeConfigClientApi()
	userInteractive := initializeUserInteractive()

	t.Run(test.Name, func(t *testing.T) {
		var userAPI fakePublicKeyUserApi

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

		// Expect an exception.
		if err == nil {
			t.Fatalf("%v failed: %+v", test.Name, login)
		}

		// asserts
		assert.Truef(
			err.Code == http.StatusUnauthorized,
			"err.Code: got %v, want %v", err.Code, http.StatusUnauthorized)
	})
}

type fakePublicKeyUserApi struct {
	UserInternalAPIForLogin
	uapi.UserLoginAPI
	uapi.ClientUserAPI
	DeletedTokens []string
}

func (ua *fakePublicKeyUserApi) QueryAccountAvailability(ctx context.Context, req *uapi.QueryAccountAvailabilityRequest, res *uapi.QueryAccountAvailabilityResponse) error {
	if req.Localpart == "invalid" {
		res.Available = false
		return nil
	}
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

func initializeUserInteractive() *UserInteractive {
	userInteractive := UserInteractive{
		Flows:    []userInteractiveFlow{},
		Types:    make(map[string]Type),
		Sessions: make(map[string][]string),
		Params:   make(map[string]interface{}),
	}

	return &userInteractive
}

func initializeConfigClientApi() *config.ClientAPI {
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
