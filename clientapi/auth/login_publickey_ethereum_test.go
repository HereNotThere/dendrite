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
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/matrix-org/dendrite/clientapi/jsonerror"
	"github.com/matrix-org/dendrite/test"
	"github.com/stretchr/testify/assert"
)

func TestLoginPublicKeyEthereum(t *testing.T) {
	// Setup
	var userAPI fakePublicKeyUserApi
	ctx := context.Background()
	loginContext := createLoginContext(t)
	wallet, _ := test.CreateTestAccount()
	message, _ := test.CreateEip4361TestMessage(wallet.PublicAddress)
	signature, _ := test.SignMessage(message.String(), wallet.PrivateKey)
	sessionId := publicKeyTestSession(
		&ctx,
		loginContext.config,
		loginContext.userInteractive,
		&userAPI,
	)

	// Escape \t and \n. Work around for marshalling and unmarshalling message.
	msgStr := test.FromEip4361MessageToString(message)
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
		loginContext.userInteractive,
		loginContext.config)

	if cleanup != nil {
		cleanup(ctx, nil)
	}

	// Asserts
	assert := assert.New(t)
	assert.Nilf(err, "err actual: %v, expected: nil", err)
	assert.NotNil(login, "login: actual: nil, expected: not nil")
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
	loginContext := createLoginContext(t)
	wallet, _ := test.CreateTestAccount()
	message, _ := test.CreateEip4361TestMessage(wallet.PublicAddress)
	sessionId := publicKeyTestSession(
		&ctx,
		loginContext.config,
		loginContext.userInteractive,
		&userAPI,
	)

	// Escape \t and \n. Work around for marshalling and unmarshalling message.
	msgStr := test.FromEip4361MessageToString(message)
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
		loginContext.userInteractive,
		loginContext.config)

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
	loginContext := createLoginContext(t)
	wallet, _ := test.CreateTestAccount()
	sessionId := publicKeyTestSession(
		&ctx,
		loginContext.config,
		loginContext.userInteractive,
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
		loginContext.userInteractive,
		loginContext.config)

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
	loginContext := createLoginContext(t)
	wallet, _ := test.CreateTestAccount()
	sessionId := publicKeyTestSession(
		&ctx,
		loginContext.config,
		loginContext.userInteractive,
		&userAPI,
	)

	body := fmt.Sprintf(`{
		"type": "m.login.publickey",
		"auth": {
			"type": "m.login.publickey.ethereum",
			"session": "%v",
			"user_id": "%v"
		}
	 }`,
		sessionId,
		wallet.PublicAddress)
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
		loginContext.userInteractive,
		loginContext.config)

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
	loginContext := createLoginContext(t)
	sessionId := publicKeyTestSession(
		&ctx,
		loginContext.config,
		loginContext.userInteractive,
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
		loginContext.userInteractive,
		loginContext.config)

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
	loginContext := createLoginContext(t)
	sessionId := publicKeyTestSession(
		&ctx,
		loginContext.config,
		loginContext.userInteractive,
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
		loginContext.userInteractive,
		loginContext.config)

	if cleanup != nil {
		cleanup(ctx, nil)
	}

	// Asserts
	assert := assert.New(t)
	assert.Truef(
		err.Code == http.StatusForbidden,
		"err.Code actual: %v, expected: %v", err.Code, http.StatusForbidden)
}
