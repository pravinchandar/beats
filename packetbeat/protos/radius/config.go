package radius

import (
	"github.com/elastic/beats/packetbeat/config"
	"github.com/elastic/beats/packetbeat/protos"
)

type radiusConfig struct {
	config.ProtocolCommon `config:",inline"`
}

var (
	defaultConfig = radiusConfig{
		ProtocolCommon: config.ProtocolCommon{
			Ports:              []int{1813},
			TransactionTimeout: protos.DefaultTransactionTimeout,
		},
	}
)
