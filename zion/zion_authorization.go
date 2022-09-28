package zion

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/joho/godotenv"
	"github.com/matrix-org/dendrite/authorization"
	log "github.com/sirupsen/logrus"
)

type contractInterface struct {
	spaceManager ZionSpaceManagerInterface
	// todo: NFT interface
}

type ZionAuthorization struct {
	localhost *contractInterface
	goerli    *contractInterface
}

func NewZionAuthorization() (authorization.Authorization, error) {
	err := godotenv.Load(".env")
	if err != nil {
		log.Errorln("error loading .env file", err)
	}

	var auth ZionAuthorization

	localhost, err := newZionSpaceManagerLocalhost("", "")
	if err != nil {
		log.Errorln("error instantiating ZionSpaceManagerLocalhost", err)
	}
	auth.localhost = localhost

	goerli, err := newZionSpaceManagerGoerli("", "")
	if err != nil {
		log.Errorln("error instantiating ZionSpaceManagerGoerli", err)
	}
	auth.goerli = goerli

	return &auth, nil
}

func (za *ZionAuthorization) IsAllowed(args authorization.AuthorizationArgs) (bool, error) {
	userIdentifier := CreateUserIdentifier(args.UserId)
	contract, err := za.getContractInterface(userIdentifier.chainId)
	if err != nil {
		return false, err
	}

	spaceId, err := contract.spaceManager.GetSpaceIdByNetworkId(nil, args.RoomId)
	if err != nil {
		return false, err
	}

	log.Printf("{ roomId: %s, spaceId: %d }\n", args.RoomId, spaceId)

	isEntitled, err := spaceManager.IsEntitled(
		nil,
		spaceId,
		big.NewInt(0),
		userIdentifier.accountAddress,
		DataTypesPermission{
			Name: args.Permission,
		})

	if err != nil {
		return false, err
	}

	return isEntitled, nil
}

func (za *ZionAuthorization) getContractInterface(chainId int) (*contractInterface, error) {
	switch chainId {
	case 1337, 31337:
		if za.localhost != nil {
			return za.localhost, nil
		}
	case 5:
		if za.goerli != nil {
			return za.goerli, nil
		}
	}

	return nil, errors.New(fmt.Sprintf("failed to get contract interface for chainId %d", chainId))
}

func (za *ZionAuthorization) getSpaceManager(chainId int) (*ZionSpaceManagerInterface, error) {
	contractInterface, err := za.getContractInterface(chainId)
	if err != nil {
		return nil, err
	}

	return &contractInterface.spaceManager, nil
}

func newZionSpaceManagerLocalhost(endpointUrl string, contractAddress string) (*contractInterface, error) {
	address := common.HexToAddress((contractAddress))
	client, err := GetEthClient(endpointUrl)

	spaceManager, err := NewZionSpaceManagerLocalhost(address, client)
	if err != nil {
		return nil, err
	}

	instance := contractInterface{
		spaceManager: spaceManager,
	}

	return &instance, nil
}

func newZionSpaceManagerGoerli(endpointUrl string, contractAddress string) (*contractInterface, error) {
	address := common.HexToAddress((contractAddress))
	client, err := GetEthClient(endpointUrl)

	spaceManager, err := NewZionSpaceManagerGoerli(address, client)
	if err != nil {
		return nil, err
	}

	instance := contractInterface{
		spaceManager: spaceManager,
	}

	return &instance, nil
}
