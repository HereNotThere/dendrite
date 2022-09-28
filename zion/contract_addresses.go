package zion

import (
	"encoding/json"
	"io/ioutil"
	"os"

	log "github.com/sirupsen/logrus"
)

type SpaceManagerContractAddresses struct {
	Spacemanager string `json:"spaceManager"`
	Usergranted  string `json:"usergranted"`
	Tokengranted string `json:"tokengranted"`
}

func loadSpaceManagerAddressesJson(filepath string) (*SpaceManagerContractAddresses, error) {
	// Open our jsonFile
	jsonFile, err := os.Open(filepath)

	// if we os.Open returns an error then handle it
	if err != nil {
		return nil, err
	}

	log.Printf("Successfully opened %s\n", filepath)

	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()

	// read our opened jsonFile as a byte array.
	byteValue, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return nil, err
	}

	var addresses SpaceManagerContractAddresses

	err = json.Unmarshal(byteValue, &addresses)
	if err != nil {
		return nil, err
	}

	return &addresses, nil
}
