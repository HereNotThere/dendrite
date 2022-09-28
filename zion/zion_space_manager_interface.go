package zion

import (
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
)

type ZionSpaceManagerInterface interface {
	GetSpaceIdByNetworkId(opts *bind.CallOpts, networkId string) (*big.Int, error)
	IsEntitled(opts *bind.CallOpts, spaceId *big.Int, roomId *big.Int, user common.Address, permission DataTypesPermission) (bool, error)
}
