package radius

import (
	"time"

	"github.com/elastic/beats/libbeat/logp"
	"github.com/urso/ucfg"

	"github.com/elastic/beats/packetbeat/protos"
	"github.com/elastic/beats/packetbeat/publish"
)

// RADIUS application level protocol analyser plugin.
type RADIUS struct {
	Ports              []int
	SendRequest        bool
	SendResponse       bool
	transactionTimeout time.Duration
	results            publish.Transactions
}

func init() {
	protos.Register("radius", New)
}

func New(
	testMode bool,
	results publish.Transactions,
	cfg *ucfg.Config,
) (protos.Plugin, error) {
	r := &RADIUS{}
	config := defaultConfig
	if !testMode {
		if err := cfg.Unpack(&config); err != nil {
			return nil, err
		}
	}

	if err := r.init(results, &config); err != nil {
		return nil, err
	}
	return r, nil
}

func (radius *RADIUS) GetPorts() []int {
	return radius.Ports
}

// Init initializes the RADIUS protocol analyser.
func (radius *RADIUS) init(results publish.Transactions, config *radiusConfig) error {
	radius.Ports = config.Ports
	radius.results = results
	return nil
}

func (radius *RADIUS) ParseUdp(pkt *protos.Packet) {
	defer logp.Recover("Radius ParseUdp")

	logp.Info("Radius", "Parsing packet addressed with %s of length %d.",
		pkt.Tuple.String(), len(pkt.Payload))

}
