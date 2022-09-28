package zion

import (
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
	localhost contractInterface
	goerli    contractInterface
}

func NewZionAuthorization() (authorization.Authorization, error) {
	err := godotenv.Load(".env")

	if err != nil {
		log.Errorln("Error loading .env file", err)
	}

	var auth ZionAuthorization

	return &auth, nil
}

func (za *ZionAuthorization) IsAllowed(args authorization.AuthorizationArgs) (bool, error) {
	userIdentifier := CreateUserIdentifier(args.UserId)
	var spaceManager ZionSpaceManagerInterface //:= getSpaceManager(userIdentifier.chainId)

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
