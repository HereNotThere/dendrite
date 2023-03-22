package zion

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/gologme/log"
	"github.com/matrix-org/dendrite/authorization"
	"github.com/matrix-org/dendrite/zion/contracts/sepolia_space"
	"github.com/matrix-org/dendrite/zion/contracts/sepolia_space_factory"
)

type SpaceContractSepolia struct {
	ethClient    *ethclient.Client
	spaceFactory *sepolia_space_factory.SepoliaSpaceFactory
	spaces       map[string]*sepolia_space.SepoliaSpace
}

func NewSpaceContractSepolia(ethClient *ethclient.Client) (*SpaceContractSepolia, error) {
	jsonAddress, err := loadSpaceFactoryAddress(11155111)
	if err != nil {
		log.Errorf("error parsing sepolia space factory contract address %v. Error: %v", jsonAddress, err)
		return nil, err
	}
	address := common.HexToAddress(jsonAddress.SpaceFactory)
	spaceFactory, err := sepolia_space_factory.NewSepoliaSpaceFactory(address, ethClient)
	if err != nil {
		log.Errorf("error fetching sepolia space factory contract with address %v. Error: %v", jsonAddress, err)
		return nil, err
	}
	// no errors.
	var spaceContract = &SpaceContractSepolia{
		ethClient:    ethClient,
		spaceFactory: spaceFactory,
		spaces:       make(map[string]*sepolia_space.SepoliaSpace),
	}
	return spaceContract, nil
}

func (za *SpaceContractSepolia) IsEntitledToSpace(
	spaceNetworkId string,
	user common.Address,
	permission authorization.Permission,
) (bool, error) {
	// get the space and check if user is entitled.
	space, err := za.getSpace(spaceNetworkId)
	if err != nil {
		return false, err
	}
	isEntitled, err := space.IsEntitledToSpace(
		nil,
		user,
		permission.String(),
	)
	if err != nil {
		return false, err
	}
	return isEntitled, nil
}

func (za *SpaceContractSepolia) IsEntitledToChannel(
	spaceNetworkId string,
	channelNetworkId string,
	user common.Address,
	permission authorization.Permission,
) (bool, error) {
	// get the space and check if user is entitled.
	space, err := za.getSpace(spaceNetworkId)
	if err != nil {
		return false, err
	}
	// channel entitlement check
	isEntitled, err := space.IsEntitledToChannel(
		nil,
		channelNetworkId,
		user,
		permission.String(),
	)
	return isEntitled, err
}

func (za *SpaceContractSepolia) IsSpaceDisabled(spaceNetworkId string) (bool, error) {
	space, err := za.getSpace(spaceNetworkId)
	if err != nil {
		return false, err
	}
	isDisabled, err := space.Disabled(nil)
	return isDisabled, err
}

func (za *SpaceContractSepolia) IsChannelDisabled(spaceNetworkId string, channelNetworkId string) (bool, error) {
	space, err := za.getSpace(spaceNetworkId)
	if err != nil {
		return false, err
	}
	channelIdHash := NetworkIdToHash(channelNetworkId)
	channel, err := space.GetChannelByHash(nil, channelIdHash)
	if err != nil {
		return false, err
	}
	return channel.Disabled, err
}

func (za *SpaceContractSepolia) getSpace(networkId string) (*sepolia_space.SepoliaSpace, error) {
	if za.spaces[networkId] == nil {
		// convert the networkId to keccak256 spaceIdHash
		spaceIdHash := NetworkIdToHash(networkId)
		// then use the spaceFactory to fetch the space address
		spaceAddress, err := za.spaceFactory.SpaceByHash(nil, spaceIdHash)
		if err != nil {
			return nil, err
		}
		// cache the space for future use
		space, err := sepolia_space.NewSepoliaSpace(spaceAddress, za.ethClient)
		if err != nil {
			return nil, err
		}
		za.spaces[networkId] = space
	}
	return za.spaces[networkId], nil
}
