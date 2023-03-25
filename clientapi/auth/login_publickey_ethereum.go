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
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/matrix-org/dendrite/clientapi/jsonerror"
	"github.com/matrix-org/dendrite/clientapi/userutil"
	"github.com/matrix-org/dendrite/setup/config"
	userapi "github.com/matrix-org/dendrite/userapi/api"
	"github.com/sirupsen/logrus"
	"github.com/spruceid/siwe-go"
)

type LoginPublicKeyEthereum struct {
	// https://github.com/tak-hntlabs/matrix-spec-proposals/blob/main/proposals/3782-matrix-publickey-login-spec.md#client-sends-login-request-with-authentication-data
	Type      string `json:"type"`
	UserId    string `json:"user_id"`
	Session   string `json:"session"`
	Message   string `json:"message"`
	Signature string `json:"signature"`

	userAPI userapi.ClientUserAPI
	config  *config.ClientAPI
}

func CreatePublicKeyEthereumHandler(
	reqBytes []byte,
	userAPI userapi.ClientUserAPI,
	config *config.ClientAPI,
) (*LoginPublicKeyEthereum, *jsonerror.MatrixError) {
	var pk LoginPublicKeyEthereum
	if err := json.Unmarshal(reqBytes, &pk); err != nil {
		return nil, jsonerror.BadJSON("auth")
	}

	pk.config = config
	pk.userAPI = userAPI
	// Case-insensitive
	pk.UserId = strings.ToLower(pk.UserId)

	return &pk, nil
}

func (pk LoginPublicKeyEthereum) GetSession() string {
	return pk.Session
}

func (pk LoginPublicKeyEthereum) GetType() string {
	return pk.Type
}

func (pk LoginPublicKeyEthereum) AccountExists(ctx context.Context) (string, *jsonerror.MatrixError) {
	localPart, _, err := userutil.ParseUsernameParam(pk.UserId, pk.config.Matrix)
	if err != nil {
		// userId does not exist
		logrus.WithError(err).Error("the address is incorrect, userId does not exist", pk.UserId)
		return "", jsonerror.Forbidden("the address is incorrect, userId does not exist")
	}

	if !pk.IsValidUserId(localPart) {
		logrus.Warn("the username is not valid", pk.UserId, localPart)
		return "", jsonerror.InvalidUsername("the username is not valid.")
	}

	res := userapi.QueryAccountAvailabilityResponse{}
	if err := pk.userAPI.QueryAccountAvailability(ctx, &userapi.QueryAccountAvailabilityRequest{
		Localpart:  localPart,
		ServerName: pk.config.Matrix.ServerName,
	}, &res); err != nil {
		logrus.WithError(err).Error("failed to check availability")
		return "", jsonerror.Unknown("failed to check availability")
	}

	if localPart == "" || res.Available {
		logrus.Warn("the address is incorrect, or the account does not exist", pk.UserId, localPart, res)
		return "", jsonerror.Forbidden("the address is incorrect, or the account does not exist")
	}

	return localPart, nil
}

var validChainAgnosticIdRegex = regexp.MustCompile("^eip155=3a[0-9]+=3a0x[0-9a-fA-F]+$")

func (pk LoginPublicKeyEthereum) IsValidUserId(userId string) bool {
	// Verify that the user ID is a valid one according to spec.
	// https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-10.md

	// Matrix ID has additional grammar requirements for user ID.
	// https://spec.matrix.org/v1.1/appendices/#user-identifiers
	// Make sure disallowed characters are escaped.
	// E.g. ":" is replaced with "=3a".

	isValid := validChainAgnosticIdRegex.MatchString(userId)

	// In addition, double check that the user ID
	// matches the authentication data in the request.
	return isValid && strings.ToLower(userId) == pk.UserId
}

func (pk LoginPublicKeyEthereum) ValidateLoginResponse() (bool, *jsonerror.MatrixError) {
	// Parse the message to extract all the fields.
	message, err := siwe.ParseMessage(pk.Message)
	if err != nil {
		return false, jsonerror.InvalidParam("auth.message")
	}

	serverName := pk.config.Matrix.ServerName

	// Check signature to verify message was not tempered
	_, err = message.Verify(pk.Signature, nil, nil, nil)
	if err != nil {
		return false, jsonerror.InvalidSignature(fmt.Sprintf("%s signature:%+v server_name:%+v messsage_domain:%+v", err.Error(), pk.Signature, serverName, message.GetDomain()))
	}

	// Check that the origin is allowed
	messageOrigin := message.GetURI()
	if !pk.isAllowedOrigin(messageOrigin) {
		return false, jsonerror.Forbidden(fmt.Sprintf("origin disallowed %s://%s", messageOrigin.Scheme, messageOrigin.Host))
	}

	// Error if the user ID does not match the signed message.
	isVerifiedUserId := pk.verifyMessageUserId(message)
	if !isVerifiedUserId {
		return false, jsonerror.InvalidUsername(pk.UserId)
	}

	// Error if the chainId is not supported by the server.
	if pk.config.PublicKeyAuthentication.Ethereum.GetChainID() != message.GetChainID() {
		return false, jsonerror.Forbidden("chainId")
	}

	// No errors.
	return true, nil
}

func (pk LoginPublicKeyEthereum) CreateLogin() *Login {
	identifier := LoginIdentifier{
		Type: "m.id.decentralizedid",
		User: pk.UserId,
	}
	login := Login{
		Identifier: identifier,
	}
	return &login
}

func (pk LoginPublicKeyEthereum) verifyMessageUserId(message *siwe.Message) bool {
	// Use info in the signed message to derive the expected user ID.
	expectedUserId := fmt.Sprintf("eip155=3a%d=3a%s", message.GetChainID(), message.GetAddress())

	// Case-insensitive comparison to make sure the user ID matches the expected
	// one derived from the signed message.
	return pk.UserId == strings.ToLower(expectedUserId)
}

func (pk LoginPublicKeyEthereum) isAllowedOrigin(uri url.URL) bool {
	for _, v := range pk.config.GetAllowedOrigins() {
		if v.Scheme == uri.Scheme && v.Host == uri.Host {
			return true
		}
	}
	return false
}
