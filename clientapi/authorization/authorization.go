package authorization

import (
	"github.com/joho/godotenv"
	"github.com/matrix-org/dendrite/authorization"
	"github.com/matrix-org/dendrite/setup/config"
	"github.com/matrix-org/dendrite/zion"
)

func NewAuthorization(cfg *config.ClientAPI) authorization.Authorization {
	// Load authorization manager for Zion
	if cfg.PublicKeyAuthentication.Ethereum.EnableAuthz {
		godotenv.Load(".env")
		auth, err := zion.NewZionAuthorization()
		if auth != nil && err == nil {
			return auth
		}
	}

	return &authorization.DefaultAuthorization{}
}
