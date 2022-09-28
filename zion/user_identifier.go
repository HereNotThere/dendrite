package zion

import "github.com/ethereum/go-ethereum/common"

type UserIdentifier struct {
	accountAddress common.Address
	chainId        int
}

func CreateUserIdentifier(matrixUserId string) UserIdentifier {
	// to do split into EIP155 user id.
	return UserIdentifier{
		accountAddress: common.HexToAddress(matrixUserId),
		chainId:        31337,
	}
}
