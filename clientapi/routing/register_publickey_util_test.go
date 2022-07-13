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

package routing

/**
No tests in this file.
Test utilities for publickey registration. Created with _test.go filename
to exclude it from production builds.
*/

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/matrix-org/dendrite/clientapi/auth"
	"github.com/matrix-org/dendrite/setup/config"
	"github.com/matrix-org/dendrite/test"
	uapi "github.com/matrix-org/dendrite/userapi/api"
)

type registerContext struct {
	config          *config.ClientAPI
	userInteractive *auth.UserInteractive
}

func createRegisterContext(t *testing.T) *registerContext {
	var userAPI fakePublicKeyUserApi
	chainIds := []int{4}

	cfg := &config.ClientAPI{
		Matrix: &config.Global{
			ServerName: test.TestServerName,
		},
		Derived:                        &config.Derived{},
		PasswordAuthenticationDisabled: true,
		PublicKeyAuthentication: config.PublicKeyAuthentication{
			Ethereum: config.EthereumAuthConfig{
				Enabled:  true,
				Version:  1,
				ChainIDs: chainIds,
			},
		},
	}

	var loginApi uapi.UserLoginAPI

	userInteractive := auth.NewUserInteractive(
		loginApi,
		&userAPI,
		cfg)

	return &registerContext{
		config:          cfg,
		userInteractive: userInteractive,
	}

}

type fakeHttpRequest struct {
	request         *http.Request
	body            []byte
	registerRequest registerRequest
}

func createFakeHttpRequest(body string) *fakeHttpRequest {
	var r registerRequest
	json.Unmarshal([]byte(body), &r)
	req, _ := http.NewRequest(http.MethodPost, "", strings.NewReader(body))
	reqBody := []byte(body)

	return &fakeHttpRequest{
		request:         req,
		body:            reqBody,
		registerRequest: r,
	}
}

type fakePublicKeyUserApi struct {
	auth.UserInternalAPIForLogin
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
