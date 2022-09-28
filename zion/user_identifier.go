package zion

import "github.com/ethereum/go-ethereum/common"

type UserIdentifier struct {
	accountAddress common.Address
	chainId        int
}

func CreateUserIdentifier(matrixUserId string) UserIdentifier {
	// to do split into EIP155 user id.
	return UserIdentifier{
		accountAddress: common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"),
		chainId:        31337,
	}
}
