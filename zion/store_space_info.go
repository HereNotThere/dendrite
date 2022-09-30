/*
Convenient function for space info mapping between Matrix room and Space contract
*/
package zion

import (
	"math/big"

	roomserver "github.com/matrix-org/dendrite/roomserver/api"
)

type StoreSpaceInfo struct {
	MatrixUserId     string
	SpaceNetworkId   string
	ChannelNetworkId string
	SpaceId          *big.Int
	ChannelId        *big.Int
	IsSpace          bool
	IsOwner          bool
}

func GetStoreSpaceInfo(roomId string, userId string, rsAPI roomserver.ClientRoomserverAPI) StoreSpaceInfo {
	return StoreSpaceInfo{
		MatrixUserId:     userId,
		SpaceNetworkId:   roomId,
		ChannelNetworkId: "",
		SpaceId:          nil,
		ChannelId:        nil,
		IsSpace:          true,
		IsOwner:          false,
	}
}
