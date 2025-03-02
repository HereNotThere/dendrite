package config

import (
	"strconv"
	"strings"

	"github.com/matrix-org/dendrite/clientapi/auth/authtypes"
)

type AuthParams interface {
	GetParams() interface{}
}

type EthereumAuthParams struct {
	Version uint `json:"version"`
	ChainID int  `json:"chain_id"`
}

func (p EthereumAuthParams) GetParams() interface{} {
	return p
}

type EthereumAuthConfig struct {
	Enabled       bool   `yaml:"enabled"`
	Version       uint   `yaml:"version"`
	NetworkUrl    string `yaml:"network_url"` // Blockchain network provider URL
	ConfigChainID string `yaml:"chain_id"`    // Blockchain chain ID. Env variable can replace this property.
	chainID       int
}

func (c *EthereumAuthConfig) GetChainID() int {
	if c.ConfigChainID != "" {
		v := strings.TrimSpace(c.ConfigChainID)
		id, err := strconv.Atoi(v)
		if err == nil {
			c.chainID = id
		}
		// No need to do this again.
		c.ConfigChainID = ""
	}
	return c.chainID
}

type PublicKeyAuthentication struct {
	Ethereum EthereumAuthConfig `yaml:"ethereum"`
}

func (pk *PublicKeyAuthentication) Enabled() bool {
	return pk.Ethereum.Enabled
}

func (pk *PublicKeyAuthentication) GetPublicKeyRegistrationFlows() []authtypes.Flow {
	var flows []authtypes.Flow
	if pk.Ethereum.Enabled {
		flows = append(flows, authtypes.Flow{Stages: []authtypes.LoginType{authtypes.LoginTypePublicKeyEthereum}})
	}

	return flows
}

func (pk *PublicKeyAuthentication) GetPublicKeyRegistrationParams() map[string]interface{} {
	params := make(map[string]interface{})
	if pk.Ethereum.Enabled {
		p := EthereumAuthParams{
			Version: pk.Ethereum.Version,
			ChainID: pk.Ethereum.GetChainID(),
		}
		params[authtypes.LoginTypePublicKeyEthereum] = p
	}

	return params
}
