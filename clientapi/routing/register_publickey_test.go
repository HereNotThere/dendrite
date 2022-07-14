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

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/matrix-org/dendrite/clientapi/auth/authtypes"
	"github.com/matrix-org/dendrite/setup/config"
	"github.com/matrix-org/dendrite/test"
	"github.com/matrix-org/util"
	"github.com/stretchr/testify/assert"
)

func TestRegisterEthereum(t *testing.T) {
	// Setup
	var userAPI fakePublicKeyUserApi
	wallet, _ := test.CreateTestAccount()
	message, _ := test.CreateEip4361TestMessage(wallet.PublicAddress)
	signature, _ := test.SignMessage(message.String(), wallet.PrivateKey)
	registerContext := createRegisterContext(t)
	sessionId := newRegistrationSession(
		t,
		wallet.Eip155UserId,
		registerContext.config,
		registerContext.userInteractive,
		&userAPI,
	)

	// Escape \t and \n. Work around for marshalling and unmarshalling message.
	msgStr := test.FromEip4361MessageToString(message)
	body := fmt.Sprintf(`{
		"username": "%v",
		"auth": {
			"type": "m.login.publickey",
			"session": "%v",
			"public_key_response": {
				"type": "m.login.publickey.ethereum",
				"session": "%v",
				"user_id": "%v",
				"message": "%v",
				"signature": "%v"
			}
		}
	 }`,
		wallet.Eip155UserId,
		sessionId,
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

	fakeReq := createFakeHttpRequest(test.Body)

	// Test
	response := handleRegistrationFlow(
		fakeReq.request,
		fakeReq.body,
		fakeReq.registerRequest,
		sessionId,
		registerContext.config,
		&userAPI,
		"",
		nil,
	)

	// Asserts
	assert := assert.New(t)
	assert.NotNil(response, "response actual: nil, expected: not nil")
	registerRes := response.JSON.(registerResponse)
	assert.Truef(
		registerRes.UserID == wallet.Eip155UserId,
		"registerRes.UserID actual: %v, expected: %v", registerRes.UserID, wallet.Eip155UserId)
	assert.NotEmptyf(
		registerRes.AccessToken,
		"registerRes.AccessToken actual: empty, expected: not empty")
}

func TestNewRegistrationSession(t *testing.T) {
	// Setup
	var userAPI fakePublicKeyUserApi

	body := fmt.Sprintf(`{
		"auth": {
			"type": "m.login.publickey",
			"username": "%v"
		}
	 }`,
		testCaip10UserId)

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
		&userAPI,
		"",
		nil,
	)

	// Asserts
	assert := assert.New(t)
	assert.NotNilf(response, "response not nil")
	assert.Truef(
		response.Code == http.StatusUnauthorized,
		"response.Code actual %v, expected %v", response.Code, http.StatusUnauthorized)
	json := response.JSON.(UserInteractiveResponse)
	assert.NotEmptyf(json.Session, "response.Session")
	assert.NotEmptyf(json.Completed, "response.Completed")
	assert.Truef(
		json.Completed[0] == authtypes.LoginStagePublicKeyNewRegistration,
		"response.Completed[0] actual %v, expected %v", json.Completed[0], authtypes.LoginStagePublicKeyNewRegistration)
	assert.Truef(
		authtypes.LoginTypePublicKeyEthereum == json.Flows[0].Stages[0],
		"response.Flows[0].Stages[0] actual: %v, expected: %v", json.Flows[0].Stages[0], authtypes.LoginTypePublicKeyEthereum)

	params := json.Params[authtypes.LoginTypePublicKeyEthereum]
	assert.NotEmptyf(
		params,
		"response.Params[\"%v\"] actual %v, expected %v",
		authtypes.LoginTypePublicKeyEthereum,
		params,
		"[object]")
	ethParams := params.(config.EthereumAuthParams)
	assert.NotEmptyf(ethParams.ChainIDs, "ChainIDs actual: empty, expected not empty")
	assert.NotEmptyf(ethParams.Nonce, "Nonce actual: \"\", expected: not empty")
	assert.NotEmptyf(ethParams.Version, "Version actual: \"\", expected: not empty")
}

func TestRegistrationUnimplementedAlgo(t *testing.T) {
	// Setup
	var userAPI fakePublicKeyUserApi
	body := fmt.Sprintf(`{
		"auth": {
			"type": "m.login.publickey.someAlgo",
			"username": "%v"
		}
	 }`,
		testCaip10UserId)

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
		&userAPI,
		"",
		nil,
	)

	// Asserts
	assert := assert.New(t)
	assert.NotNilf(response, "response not nil")
	assert.Truef(
		response.Code == http.StatusNotImplemented,
		"response.Code actual %v, expected %v", response.Code, http.StatusNotImplemented)
}
