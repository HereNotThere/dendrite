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

package web3

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

type CreateTransactionSignerArgs struct {
	PrivateKey string
	ChainId    int64
	Client     *ethclient.Client
	GasValue   int64 // in wei
	GasLimit   int64 // in units
}

func CreateTransactionSigner(args CreateTransactionSignerArgs) (*bind.TransactOpts, error) {
	privateKey, err := crypto.HexToECDSA(args.PrivateKey)
	if err != nil {
		return nil, err
	}

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("cannot create public key ECDSA")
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	nonce, err := args.Client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		return nil, err
	}

	gasPrice, err := args.Client.SuggestGasPrice((context.Background()))
	if err != nil {
		return nil, err
	}

	signer, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(args.ChainId))
	if err != nil {
		return nil, err
	}

	signer.Nonce = big.NewInt(int64(nonce))
	signer.Value = big.NewInt(args.GasValue)
	signer.GasLimit = uint64(args.GasLimit)
	signer.GasPrice = gasPrice

	fmt.Printf("{ nonce: %d, value: %d, gasLimit: %d, gasPrice: %d }\n",
		signer.Nonce,
		signer.Value,
		signer.GasLimit,
		signer.GasPrice,
	)

	return signer, nil
}
