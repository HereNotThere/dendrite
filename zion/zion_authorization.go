package zion

import (
	_ "embed"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/joho/godotenv"
	"github.com/matrix-org/dendrite/authorization"
	roomserver "github.com/matrix-org/dendrite/roomserver/api"
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

type ZionAuthorization struct {
	spaceManagerLocalhost *ZionSpaceManagerLocalhost
	spaceManagerGoerli    *ZionSpaceManagerGoerli
	store                 Store
}

func NewZionAuthorization(rsAPI roomserver.ClientRoomserverAPI) (authorization.Authorization, error) {
	err := godotenv.Load(".env")
	if err != nil {
		log.Errorln("error loading .env file", err)
	}

	var auth ZionAuthorization

	auth.store = NewStore(rsAPI)

	localhost, err := newZionSpaceManagerLocalhost(os.Getenv(localhostEndpointUrl))
	if err != nil {
		log.Errorln("error instantiating ZionSpaceManagerLocalhost", err)
	}
	auth.spaceManagerLocalhost = localhost

	goerli, err := newZionSpaceManagerGoerli(os.Getenv(goerliEndpointUrl))
	if err != nil {
		log.Errorln("error instantiating ZionSpaceManagerGoerli", err)
	}
	auth.spaceManagerGoerli = goerli

	return &auth, nil
}

func (za *ZionAuthorization) IsAllowed(args authorization.AuthorizationArgs) (bool, error) {
	userIdentifier := CreateUserIdentifier(args.UserId)
	permission := DataTypesPermission{
		Name: args.Permission,
	}

	// Find out if roomId is a space or a channel.
	storeInfo := za.store.GetStoreSpaceInfo(args.RoomId, userIdentifier)

	switch userIdentifier.ChainId {
	case 1337, 31337:
		return za.isAllowedLocalhost(storeInfo, userIdentifier.AccountAddress, permission)
	case 5:
		return za.isAllowedGoerli(storeInfo, userIdentifier.AccountAddress, permission)
	default:
		log.Errorf("Unsupported chain id: %d\n", userIdentifier.ChainId)
	}

	return false, nil
}

func (za *ZionAuthorization) isAllowedLocalhost(
	storeInfo StoreSpaceInfo,
	user common.Address,
	permission DataTypesPermission,
) (bool, error) {
	if storeInfo.IsOwner {
		return true, nil
	}

	if za.spaceManagerLocalhost != nil {
		spaceId, err := za.spaceManagerLocalhost.GetSpaceIdByNetworkId(nil, storeInfo.SpaceNetworkId)
		if err != nil {
			return false, err
		}

		isEntitled, err := za.spaceManagerLocalhost.IsEntitled(
			nil,
			spaceId,
			big.NewInt(0),
			user,
			permission,
		)

		if err != nil {
			return false, err
		}

		return isEntitled, nil
	}

	return false, nil
}

func (za *ZionAuthorization) isAllowedGoerli(
	storeInfo StoreSpaceInfo,
	user common.Address,
	permission DataTypesPermission,
) (bool, error) {
	if storeInfo.IsOwner {
		return true, nil
	}

	if za.spaceManagerGoerli != nil {
		spaceId, err := za.spaceManagerGoerli.GetSpaceIdByNetworkId(nil, storeInfo.SpaceNetworkId)
		if err != nil {
			return false, err
		}

		isEntitled, err := za.spaceManagerGoerli.IsEntitled(
			nil,
			spaceId,
			big.NewInt(0),
			user,
			permission,
		)

		if err != nil {
			return false, err
		}

		return isEntitled, nil
	}

	return false, nil
}

func newZionSpaceManagerLocalhost(endpointUrl string) (*ZionSpaceManagerLocalhost, error) {
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

	return spaceManager, nil
}

func newZionSpaceManagerGoerli(endpointUrl string) (*ZionSpaceManagerGoerli, error) {
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

	return spaceManager, nil
}
