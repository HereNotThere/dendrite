// Copyright 2017 Vector Creations Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/joho/godotenv"
	"github.com/matrix-org/dendrite/clientapi/auth/authtypes"
	"github.com/matrix-org/dendrite/internal/mapsutil"
	"github.com/matrix-org/gomatrixserverlib"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ed25519"
	"gopkg.in/yaml.v2"

	jaegerconfig "github.com/uber/jaeger-client-go/config"
	jaegermetrics "github.com/uber/jaeger-lib/metrics"
)

// keyIDRegexp defines allowable characters in Key IDs.
var keyIDRegexp = regexp.MustCompile("^ed25519:[a-zA-Z0-9_]+$")

// Version is the current version of the config format.
// This will change whenever we make breaking changes to the config format.
const Version = 2

// Dendrite contains all the config used by a dendrite process.
// Relative paths are resolved relative to the current working directory
type Dendrite struct {
	// The version of the configuration file.
	// If the version in a file doesn't match the current dendrite config
	// version then we can give a clear error message telling the user
	// to update their config file to the current version.
	// The version of the file should only be different if there has
	// been a breaking change to the config file format.
	Version int `yaml:"version"`

	Global        Global        `yaml:"global"`
	AppServiceAPI AppServiceAPI `yaml:"app_service_api"`
	ClientAPI     ClientAPI     `yaml:"client_api"`
	FederationAPI FederationAPI `yaml:"federation_api"`
	KeyServer     KeyServer     `yaml:"key_server"`
	MediaAPI      MediaAPI      `yaml:"media_api"`
	RoomServer    RoomServer    `yaml:"room_server"`
	SyncAPI       SyncAPI       `yaml:"sync_api"`
	UserAPI       UserAPI       `yaml:"user_api"`
	RelayAPI      RelayAPI      `yaml:"relay_api"`

	MSCs MSCs `yaml:"mscs"`

	// The config for tracing the dendrite servers.
	Tracing struct {
		// Set to true to enable tracer hooks. If false, no tracing is set up.
		Enabled bool `yaml:"enabled"`
		// The config for the jaeger opentracing reporter.
		Jaeger jaegerconfig.Configuration `yaml:"jaeger"`
	} `yaml:"tracing"`

	// The config for logging informations. Each hook will be added to logrus.
	Logging []LogrusHook `yaml:"logging"`

	AllowedOrigins []string `yaml:"allowed_origins"`

	// Any information derived from the configuration options for later use.
	Derived Derived `yaml:"-"`
}

// TODO: Kill Derived
type Derived struct {
	Registration struct {
		// Flows is a slice of flows, which represent one possible way that the client can authenticate a request.
		// http://matrix.org/docs/spec/HEAD/client_server/r0.3.0.html#user-interactive-authentication-api
		// As long as the generated flows only rely on config file options,
		// we can generate them on startup and store them until needed
		Flows []authtypes.Flow `json:"flows"`

		// Params that need to be returned to the client during
		// registration in order to complete registration stages.
		Params map[string]interface{} `json:"params"`
	}

	// Application services parsed from their config files
	// The paths of which were given above in the main config file
	ApplicationServices []ApplicationService

	// Meta-regexes compiled from all exclusive application service
	// Regexes.
	//
	// When a user registers, we check that their username does not match any
	// exclusive application service namespaces
	ExclusiveApplicationServicesUsernameRegexp *regexp.Regexp
	// When a user creates a room alias, we check that it isn't already
	// reserved by an application service
	ExclusiveApplicationServicesAliasRegexp *regexp.Regexp
	// Note: An Exclusive Regex for room ID isn't necessary as we aren't blocking
	// servers from creating RoomIDs in exclusive application service namespaces
}

// A Path on the filesystem.
type Path string

// A DataSource for opening a postgresql database using lib/pq.
type DataSource string

func (d DataSource) IsSQLite() bool {
	return strings.HasPrefix(string(d), "file:")
}

func (d DataSource) IsPostgres() bool {
	// commented line may not always be true?
	// return strings.HasPrefix(string(d), "postgres:")
	return !d.IsSQLite()
}

// A Topic in kafka.
type Topic string

// An Address to listen on.
type Address string

// An HTTPAddress to listen on, starting with either http:// or https://.
type HTTPAddress string

func (h HTTPAddress) Address() (Address, error) {
	url, err := url.Parse(string(h))
	if err != nil {
		return "", err
	}
	return Address(url.Host), nil
}

// FileSizeBytes is a file size in bytes
type FileSizeBytes int64

// ThumbnailSize contains a single thumbnail size configuration
type ThumbnailSize struct {
	// Maximum width of the thumbnail image
	Width int `yaml:"width"`
	// Maximum height of the thumbnail image
	Height int `yaml:"height"`
	// ResizeMethod is one of crop or scale.
	// crop scales to fill the requested dimensions and crops the excess.
	// scale scales to fit the requested dimensions and one dimension may be smaller than requested.
	ResizeMethod string `yaml:"method,omitempty"`
}

// LogrusHook represents a single logrus hook. At this point, only parsing and
// verification of the proper values for type and level are done.
// Validity/integrity checks on the parameters are done when configuring logrus.
type LogrusHook struct {
	// The type of hook, currently only "file" is supported.
	Type string `yaml:"type"`

	// The level of the logs to produce. Will output only this level and above.
	Level string `yaml:"level"`

	// The parameters for this hook.
	Params map[string]interface{} `yaml:"params"`
}

// ConfigErrors stores problems encountered when parsing a config file.
// It implements the error interface.
type ConfigErrors []string

// Load a yaml config file for a server run as multiple processes or as a monolith.
// Checks the config to ensure that it is valid.
func Load(configPath string) (*Dendrite, error) {
	configData, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	basePath, err := filepath.Abs(".")
	if err != nil {
		return nil, err
	}
	// Pass the current working directory and os.ReadFile so that they can
	// be mocked in the tests
	return loadConfig(basePath, configData, os.ReadFile)
}

func loadConfig(
	basePath string,
	configData []byte,
	readFile func(string) ([]byte, error),
) (*Dendrite, error) {
	var c Dendrite
	c.Defaults(DefaultOpts{
		Generate:       false,
		SingleDatabase: true,
	})

	var err error
	if err = yaml.Unmarshal(configData, &c); err != nil {
		return nil, err
	}

	if err = c.check(); err != nil {
		return nil, err
	}

	privateKeyPath := absPath(basePath, c.Global.PrivateKeyPath)
	if c.Global.KeyID, c.Global.PrivateKey, err = LoadMatrixKey(privateKeyPath, readFile); err != nil {
		return nil, fmt.Errorf("failed to load private_key: %w", err)
	}

	for _, v := range c.Global.VirtualHosts {
		if v.KeyValidityPeriod == 0 {
			v.KeyValidityPeriod = c.Global.KeyValidityPeriod
		}
		if v.PrivateKeyPath == "" || v.PrivateKey == nil || v.KeyID == "" {
			v.KeyID = c.Global.KeyID
			v.PrivateKey = c.Global.PrivateKey
			continue
		}
		privateKeyPath := absPath(basePath, v.PrivateKeyPath)
		if v.KeyID, v.PrivateKey, err = LoadMatrixKey(privateKeyPath, readFile); err != nil {
			return nil, fmt.Errorf("failed to load private_key for virtualhost %s: %w", v.ServerName, err)
		}
	}

	for _, key := range c.Global.OldVerifyKeys {
		switch {
		case key.PrivateKeyPath != "":
			var oldPrivateKeyData []byte
			oldPrivateKeyPath := absPath(basePath, key.PrivateKeyPath)
			oldPrivateKeyData, err = readFile(oldPrivateKeyPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read %q: %w", oldPrivateKeyPath, err)
			}

			// NOTSPEC: Ordinarily we should enforce key ID formatting, but since there are
			// a number of private keys out there with non-compatible symbols in them due
			// to lack of validation in Synapse, we won't enforce that for old verify keys.
			keyID, privateKey, perr := readKeyPEM(oldPrivateKeyPath, oldPrivateKeyData, false)
			if perr != nil {
				return nil, fmt.Errorf("failed to parse %q: %w", oldPrivateKeyPath, perr)
			}

			key.KeyID = keyID
			key.PrivateKey = privateKey
			key.PublicKey = gomatrixserverlib.Base64Bytes(privateKey.Public().(ed25519.PublicKey))

		case key.KeyID == "":
			return nil, fmt.Errorf("'key_id' must be specified if 'public_key' is specified")

		case len(key.PublicKey) == ed25519.PublicKeySize:
			continue

		case len(key.PublicKey) > 0:
			return nil, fmt.Errorf("the supplied 'public_key' is the wrong length")

		default:
			return nil, fmt.Errorf("either specify a 'private_key' path or supply both 'public_key' and 'key_id'")
		}
	}

	c.MediaAPI.AbsBasePath = Path(absPath(basePath, c.MediaAPI.BasePath))

	// Generate data from config options
	err = c.Derive()
	if err != nil {
		return nil, err
	}

	c.Wiring()
	return &c, nil
}

func LoadMatrixKey(privateKeyPath string, readFile func(string) ([]byte, error)) (gomatrixserverlib.KeyID, ed25519.PrivateKey, error) {
	privateKeyData, err := readFile(privateKeyPath)
	if err != nil {
		return "", nil, err
	}
	return readKeyPEM(privateKeyPath, privateKeyData, true)
}

// Derive generates data that is derived from various values provided in
// the config file.
func (config *Dendrite) Derive() error {
	// Replace selected config with env variables.
	config.replaceWithEnvVariables()

	// Determine registrations flows based off config values

	config.Derived.Registration.Params = make(map[string]interface{})

	// TODO: Add email auth type
	// TODO: Add MSISDN auth type

	if config.ClientAPI.RecaptchaEnabled {
		config.Derived.Registration.Params[authtypes.LoginTypeRecaptcha] = map[string]string{"public_key": config.ClientAPI.RecaptchaPublicKey}
		config.Derived.Registration.Flows = append(config.Derived.Registration.Flows,
			authtypes.Flow{Stages: []authtypes.LoginType{authtypes.LoginTypeRecaptcha}})
	} else if !config.ClientAPI.PasswordAuthenticationDisabled {
		config.Derived.Registration.Flows = append(config.Derived.Registration.Flows,
			authtypes.Flow{Stages: []authtypes.LoginType{authtypes.LoginTypeDummy}})
	}
	if config.ClientAPI.PublicKeyAuthentication.Enabled() {
		pkFlows := config.ClientAPI.PublicKeyAuthentication.GetPublicKeyRegistrationFlows()
		if pkFlows != nil {
			config.Derived.Registration.Flows = append(config.Derived.Registration.Flows, pkFlows...)
		}
		pkParams := config.ClientAPI.PublicKeyAuthentication.GetPublicKeyRegistrationParams()
		if pkParams != nil {
			config.Derived.Registration.Params = mapsutil.MapsUnion(config.Derived.Registration.Params, pkParams)
		}
	}

	// Load application service configuration files
	if err := loadAppServices(&config.AppServiceAPI, &config.Derived); err != nil {
		return err
	}

	return nil
}

type DefaultOpts struct {
	Generate       bool
	SingleDatabase bool
}

// SetDefaults sets default config values if they are not explicitly set.
func (c *Dendrite) Defaults(opts DefaultOpts) {
	c.Version = Version

	c.Global.Defaults(opts)
	c.ClientAPI.Defaults(opts)
	c.FederationAPI.Defaults(opts)
	c.KeyServer.Defaults(opts)
	c.MediaAPI.Defaults(opts)
	c.RoomServer.Defaults(opts)
	c.SyncAPI.Defaults(opts)
	c.UserAPI.Defaults(opts)
	c.AppServiceAPI.Defaults(opts)
	c.RelayAPI.Defaults(opts)
	c.MSCs.Defaults(opts)
	c.Wiring()
}

func (c *Dendrite) Verify(configErrs *ConfigErrors) {
	type verifiable interface {
		Verify(configErrs *ConfigErrors)
	}
	for _, c := range []verifiable{
		&c.Global, &c.ClientAPI, &c.FederationAPI,
		&c.KeyServer, &c.MediaAPI, &c.RoomServer,
		&c.SyncAPI, &c.UserAPI,
		&c.AppServiceAPI, &c.RelayAPI, &c.MSCs,
	} {
		c.Verify(configErrs)
	}
}

func (c *Dendrite) Wiring() {
	c.Global.JetStream.Matrix = &c.Global
	c.ClientAPI.Matrix = &c.Global
	c.FederationAPI.Matrix = &c.Global
	c.KeyServer.Matrix = &c.Global
	c.MediaAPI.Matrix = &c.Global
	c.RoomServer.Matrix = &c.Global
	c.SyncAPI.Matrix = &c.Global
	c.UserAPI.Matrix = &c.Global
	c.AppServiceAPI.Matrix = &c.Global
	c.RelayAPI.Matrix = &c.Global
	c.MSCs.Matrix = &c.Global

	c.ClientAPI.Derived = &c.Derived
	c.AppServiceAPI.Derived = &c.Derived
	c.ClientAPI.MSCs = &c.MSCs
}

// Error returns a string detailing how many errors were contained within a
// configErrors type.
func (errs ConfigErrors) Error() string {
	if len(errs) == 1 {
		return errs[0]
	}
	return fmt.Sprintf(
		"%s (and %d other problems)", errs[0], len(errs)-1,
	)
}

// Add appends an error to the list of errors in this configErrors.
// It is a wrapper to the builtin append and hides pointers from
// the client code.
// This method is safe to use with an uninitialized configErrors because
// if it is nil, it will be properly allocated.
func (errs *ConfigErrors) Add(str string) {
	*errs = append(*errs, str)
}

// checkNotEmpty verifies the given value is not empty in the configuration.
// If it is, adds an error to the list.
func checkNotEmpty(configErrs *ConfigErrors, key, value string) {
	if value == "" {
		configErrs.Add(fmt.Sprintf("missing config key %q", key))
	}
}

// checkPositive verifies the given value is positive (zero included)
// in the configuration. If it is not, adds an error to the list.
func checkPositive(configErrs *ConfigErrors, key string, value int64) {
	if value < 0 {
		configErrs.Add(fmt.Sprintf("invalid value for config key %q: %d", key, value))
	}
}

// checkLogging verifies the parameters logging.* are valid.
func (config *Dendrite) checkLogging(configErrs *ConfigErrors) {
	for _, logrusHook := range config.Logging {
		checkNotEmpty(configErrs, "logging.type", string(logrusHook.Type))
		checkNotEmpty(configErrs, "logging.level", string(logrusHook.Level))
	}
}

// check returns an error type containing all errors found within the config
// file.
func (config *Dendrite) check() error { // monolithic
	var configErrs ConfigErrors

	if config.Version != Version {
		configErrs.Add(fmt.Sprintf(
			"config version is %q, expected %q - this means that the format of the configuration "+
				"file has changed in some significant way, so please revisit the sample config "+
				"and ensure you are not missing any important options that may have been added "+
				"or changed recently!",
			config.Version, Version,
		))
		return configErrs
	}

	config.checkLogging(&configErrs)

	// Due to how Golang manages its interface types, this condition is not redundant.
	// In order to get the proper behaviour, it is necessary to return an explicit nil
	// and not a nil configErrors.
	// This is because the following equalities hold:
	// error(nil) == nil
	// error(configErrors(nil)) != nil
	if configErrs != nil {
		return configErrs
	}
	return nil
}

// absPath returns the absolute path for a given relative or absolute path.
func absPath(dir string, path Path) string {
	if filepath.IsAbs(string(path)) {
		// filepath.Join cleans the path so we should clean the absolute paths as well for consistency.
		return filepath.Clean(string(path))
	}
	return filepath.Join(dir, string(path))
}

func readKeyPEM(path string, data []byte, enforceKeyIDFormat bool) (gomatrixserverlib.KeyID, ed25519.PrivateKey, error) {
	for {
		var keyBlock *pem.Block
		keyBlock, data = pem.Decode(data)
		if data == nil {
			return "", nil, fmt.Errorf("no matrix private key PEM data in %q", path)
		}
		if keyBlock == nil {
			return "", nil, fmt.Errorf("keyBlock is nil %q", path)
		}
		if keyBlock.Type == "MATRIX PRIVATE KEY" {
			keyID := keyBlock.Headers["Key-ID"]
			if keyID == "" {
				return "", nil, fmt.Errorf("missing key ID in PEM data in %q", path)
			}
			if !strings.HasPrefix(keyID, "ed25519:") {
				return "", nil, fmt.Errorf("key ID %q doesn't start with \"ed25519:\" in %q", keyID, path)
			}
			if enforceKeyIDFormat && !keyIDRegexp.MatchString(keyID) {
				return "", nil, fmt.Errorf("key ID %q in %q contains illegal characters (use a-z, A-Z, 0-9 and _ only)", keyID, path)
			}
			_, privKey, err := ed25519.GenerateKey(bytes.NewReader(keyBlock.Bytes))
			if err != nil {
				return "", nil, err
			}
			return gomatrixserverlib.KeyID(keyID), privKey, nil
		}
	}
}

// SetupTracing configures the opentracing using the supplied configuration.
func (config *Dendrite) SetupTracing() (closer io.Closer, err error) {
	if !config.Tracing.Enabled {
		return io.NopCloser(bytes.NewReader([]byte{})), nil
	}
	return config.Tracing.Jaeger.InitGlobalTracer(
		"Dendrite",
		jaegerconfig.Logger(logrusLogger{logrus.StandardLogger()}),
		jaegerconfig.Metrics(jaegermetrics.NullFactory),
	)
}

/*
*
Replace selected config with environment variables
*/

func (config *Dendrite) replaceWithEnvVariables() {
	// If env variable is set, get the value from the env
	// variable and replace it in each supported field.

	err := godotenv.Load(".env")
	if err != nil {
		logrus.Errorln("error loading .env file", err)
	}

	config.Global.ServerName = gomatrixserverlib.ServerName(
		replaceWithEnvVariables(string(config.Global.ServerName)),
	)
	logrus.Infof("Matrix ServerName=%s", config.Global.ServerName)

	config.Global.DatabaseOptions.ConnectionString = DataSource(
		replaceWithEnvVariables(
			string(config.Global.DatabaseOptions.ConnectionString),
		),
	)

	if config.ClientAPI.PublicKeyAuthentication.Ethereum.Enabled {
		config.ClientAPI.PublicKeyAuthentication.Ethereum.ConfigChainID =
			replaceWithEnvVariables(config.ClientAPI.PublicKeyAuthentication.Ethereum.ConfigChainID)

		config.ClientAPI.PublicKeyAuthentication.Ethereum.NetworkUrl =
			replaceWithEnvVariables(config.ClientAPI.PublicKeyAuthentication.Ethereum.NetworkUrl)

		logrus.Infof(
			"Supported Ethereum chain_id=%v, network_url=%v",
			config.ClientAPI.PublicKeyAuthentication.Ethereum.ConfigChainID,
			config.ClientAPI.PublicKeyAuthentication.Ethereum.NetworkUrl,
		)
	}
}

var regexpEnvVariables = regexp.MustCompile(`\$\{(?P<Var>\w+)\}`)
var varIndex = regexpEnvVariables.SubexpIndex("Var")

func replaceWithEnvVariables(value string) string {
	matches := regexpEnvVariables.FindAllStringSubmatch(value, -1)
	for _, m := range matches {
		if varIndex < len(m) {
			envValue := os.Getenv(m[varIndex])
			value = strings.ReplaceAll(value, fmt.Sprintf("${%s}", m[varIndex]), envValue)
		}
	}
	return value
}

// logrusLogger is a small wrapper that implements jaeger.Logger using logrus.
type logrusLogger struct {
	l *logrus.Logger
}

func (l logrusLogger) Error(msg string) {
	l.l.Error(msg)
}

func (l logrusLogger) Infof(msg string, args ...interface{}) {
	l.l.Infof(msg, args...)
}
