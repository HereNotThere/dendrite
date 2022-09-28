package zion

import (
	_ "embed"
	"fmt"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/joho/godotenv"
	"github.com/matrix-org/dendrite/authorization"
	log "github.com/sirupsen/logrus"
)

const (
	localhostEndpointUrl = "LOCALHOST_ENDPOINT" // .env
	goerliEndpointUrl    = "GOERLI_ENDPOINT"    // .env
)

//go:embed contracts/localhost/addresses/space-manager.json
var localhostJson []byte

//go:embed contracts/goerli/addresses/space-manager.json
var goerliJson []byte

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

	localhost, err := newZionSpaceManagerLocalhost(os.Getenv(localhostEndpointUrl))
	if err != nil {
		log.Errorln("error instantiating ZionSpaceManagerLocalhost", err)
	}
	auth.localhost = localhost

	goerli, err := newZionSpaceManagerGoerli(os.Getenv(goerliEndpointUrl))
	if err != nil {
		log.Errorln("error instantiating ZionSpaceManagerGoerli", err)
	}
	auth.goerli = goerli

	return &auth, nil
}

func (za *ZionAuthorization) IsAllowed(args authorization.AuthorizationArgs) (bool, error) {
	userIdentifier := CreateUserIdentifier(args.UserId)
	spaceManager, err := za.getSpaceManager(userIdentifier.chainId)
	if err != nil {
		return false, err
	}

	spaceId, err := spaceManager.GetSpaceIdByNetworkId(nil, args.RoomId)
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

	return nil, fmt.Errorf("failed to get contract interface for chainId %d", chainId)
}

func (za *ZionAuthorization) getSpaceManager(chainId int) (ZionSpaceManagerInterface, error) {
	contractInterface, err := za.getContractInterface(chainId)
	if err != nil {
		return nil, err
	}

	return contractInterface.spaceManager, nil
}

func newZionSpaceManagerLocalhost(endpointUrl string) (*contractInterface, error) {
	addresses, err := loadSpaceManagerAddresses(localhostJson)
	if err != nil {
		return nil, err
	}

	address := common.HexToAddress(addresses.Spacemanager)

	client, err := GetEthClient(endpointUrl)
	if err != nil {
		return nil, err
	}

	spaceManager, err := NewZionSpaceManagerLocalhost(address, client)
	if err != nil {
		return nil, err
	}

	instance := contractInterface{
		spaceManager: spaceManager,
	}

	return &instance, nil
}

func newZionSpaceManagerGoerli(endpointUrl string) (*contractInterface, error) {
	addresses, err := loadSpaceManagerAddresses(goerliJson)
	if err != nil {
		return nil, err
	}

	address := common.HexToAddress((addresses.Spacemanager))

	client, err := GetEthClient(endpointUrl)
	if err != nil {
		return nil, err
	}

	spaceManager, err := NewZionSpaceManagerGoerli(address, client)
	if err != nil {
		return nil, err
	}

	instance := contractInterface{
		spaceManager: spaceManager,
	}

	return &instance, nil
}
