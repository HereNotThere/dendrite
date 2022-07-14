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
	"net/http"
	"testing"

	"github.com/matrix-org/dendrite/clientapi/auth/authtypes"
	"github.com/matrix-org/dendrite/setup/config"
	"github.com/matrix-org/util"
	"github.com/stretchr/testify/assert"
)

func TestNewRegistrationSession(t *testing.T) {
	// Setup
	var userAPI fakePublicKeyUserApi

	test := struct {
		Body string
	}{
		Body: `{
			"type": "m.login.publickey",
			"auth": {
				"type": "m.login.publickey"
			}
		 }`,
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
	assert.Equal(authtypes.LoginType(authtypes.LoginTypePublicKeyEthereum), json.Flows[0].Stages[0])
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

func RegistrationUnimplementedAlgo(t *testing.T) {
	// Setup
	var userAPI fakePublicKeyUserApi

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
