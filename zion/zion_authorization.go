package zion

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/matrix-org/dendrite/authorization"
	"github.com/matrix-org/dendrite/web3"
)

type contractLocalhost struct {
	address      *common.Address
	spaceManager *ZionSpaceManagerLocalhost
	client       *ethclient.Client
}

type contractGoerli struct {
	address      *common.Address
	spaceManager *ZionSpaceManagerGoerli
	client       *ethclient.Client
}

type contractProviders struct {
	localhost contractLocalhost
	goerli    contractGoerli
}

type ZionAuthorization struct {
	Client                      *ethclient.Client
	SpaceManager                *ZionSpaceManagerLocalhost
	spaceManagerContractAddress common.Address
}

func NewZionAuthorization() (authorization.Authorization, error) {
	client, err := web3.GetEthClient(args.Web3ProviderUrl)

	if err != nil {
		return nil, err
	}

	fmt.Printf("Connected to the web3 provider %s\n", args.Web3ProviderUrl)

	var auth ZionAuthorization

	auth.spaceManagerContractAddress = common.HexToAddress(args.SpaceManagerContractAddress)
	auth.Client = client

	spaceManager, err := auth.newZionSpaceManagerLocalhost(auth.spaceManagerContractAddress)
	if err != nil {
		return nil, err
	}

	fmt.Println("ZionSpaceManager contract is loaded")

	auth.SpaceManager = spaceManager

	return &auth, nil
}

func (za *ZionAuthorization) IsAllowed(args authorization.AuthorizationArgs) (bool, error) {
	address := common.HexToAddress(args.UserId)

	spaceId, err := za.SpaceManager.GetSpaceIdByNetworkId(nil, args.RoomId)
	if err != nil {
		return false, err
	}

	fmt.Printf("{ roomId: %s, spaceId: %d }\n", args.RoomId, spaceId)

	isEntitled, err := za.SpaceManager.IsEntitled(
		nil,
		spaceId,
		big.NewInt(0),
		address,
		DataTypesPermission{
			Name: args.Permission,
		})
	if err != nil {
		return false, err
	}

	return isEntitled, nil
}

func (za *ZionAuthorization) newZionSpaceManagerLocalhost(address common.Address) (*ZionSpaceManagerLocalhost, error) {
	instance, err := NewZionSpaceManagerLocalhost(address, za.Client)
	if err != nil {
		return nil, err
	}

	return instance, nil
}
