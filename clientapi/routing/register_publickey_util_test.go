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
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/matrix-org/dendrite/clientapi/auth"
	"github.com/matrix-org/dendrite/internal/mapsutil"
	"github.com/matrix-org/dendrite/setup/config"
	"github.com/matrix-org/dendrite/test"
	"github.com/matrix-org/dendrite/userapi/api"
	uapi "github.com/matrix-org/dendrite/userapi/api"
	"github.com/matrix-org/util"
)

const testCaip10UserId = "eip155=3a1=3a0xab16a96d359ec26a11e2c2b3d8f8b8942d5bfcdb"

type registerContext struct {
	config          *config.ClientAPI
	userInteractive *auth.UserInteractive
}

func createRegisterContext(t *testing.T) *registerContext {
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

	pkFlows := cfg.PublicKeyAuthentication.GetPublicKeyRegistrationFlows()
	cfg.Derived.Registration.Flows = append(cfg.Derived.Registration.Flows, pkFlows...)
	pkParams := cfg.PublicKeyAuthentication.GetPublicKeyRegistrationParams()
	cfg.Derived.Registration.Params = mapsutil.MapsUnion(cfg.Derived.Registration.Params, pkParams)

	var userAPI fakePublicKeyUserApi
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
	req, _ := http.NewRequest(http.MethodPost, "", strings.NewReader(body))
	reqBody := []byte(body)
	json.Unmarshal([]byte(body), &r)

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

func (ua *fakePublicKeyUserApi) PerformAccountCreation(
	ctx context.Context,
	req *uapi.PerformAccountCreationRequest,
	res *uapi.PerformAccountCreationResponse) error {
	res.AccountCreated = true
	res.Account = &api.Account{
		AppServiceID: req.AppServiceID,
		Localpart:    req.Localpart,
		ServerName:   test.TestServerName,
		UserID:       fmt.Sprintf("@%s:%s", req.Localpart, test.TestServerName),
		AccountType:  req.AccountType,
	}
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

func newRegistrationSession(
	t *testing.T,
	userId string,
	cfg *config.ClientAPI,
	userInteractive *auth.UserInteractive,
	userAPI *fakePublicKeyUserApi,
) string {
	body := fmt.Sprintf(`{
		"auth": {
			"type": "m.login.publickey",
			"username": "%v"
		}
	 }`,
		userId)

	test := struct {
		Body string
	}{
		Body: body,
	}

	fakeReq := createFakeHttpRequest(test.Body)
	sessionID := util.RandomString(sessionIDLength)
	registerContext := createRegisterContext(t)

	// Test
	response := handleRegistrationFlow(
		fakeReq.request,
		fakeReq.body,
		fakeReq.registerRequest,
		sessionID,
		registerContext.config,
		userAPI,
		"",
		nil,
	)

	json := response.JSON.(UserInteractiveResponse)
	return json.Session
}
