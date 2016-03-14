package radius

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/urso/ucfg"
	"time"

	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/packetbeat/protos"
	"github.com/elastic/beats/packetbeat/publish"
)

type pktIdChan struct {
	pktId    uint8
	response chan int
}

const (
	ACCESS_REQUEST      = 1
	ACCESS_ACCEPT       = 2
	ACCESS_REJECT       = 3
	ACCOUNTING_REQUEST  = 4
	ACCOUNTING_RESPONSE = 5
	ACCESS_CHALLENGE    = 11
)

// RADIUS application level protocol analyser plugin.
type RADIUS struct {
	Ports              []int
	SendRequest        bool
	SendResponse       bool
	transactionTimeout time.Duration
	results            publish.Transactions

	// Uniquely identfies a request by a NAS or a response
	// sent by a RADIUS server. The value is the packet identifier
	// from the RADIUS payload.
	transaction map[common.HashableIpPortTuple]pktIdChan
}

// The captured RADIUS payload
type radiusPayload struct {
	code          uint8
	identifier    uint8
	length        uint16
	authenticator [16]byte
	attributes    []byte
	//NAS_ip:NAS_port:radius_server_ip:radius_server_port
	ipPortHash common.HashableIpPortTuple
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

// Init the RADIUS protocol analyser.
func (radius *RADIUS) init(results publish.Transactions, config *radiusConfig) error {
	radius.Ports = config.Ports
	radius.results = results
	radius.transaction = make(map[common.HashableIpPortTuple]pktIdChan)
	return nil
}

// Gateway function to analysing the protocol. This function does the following
// 1. Decodes and performs sanity checking on the received payload
// 2. Delegates control to an appropriate Type handler
func (radius *RADIUS) ParseUdp(pkt *protos.Packet) {

	//XXX Process error
	rPayload, _ := sanitiseRadius(pkt)

	switch rPayload.code {
	case ACCESS_REQUEST:
		go radiusReqHandler(rPayload, radius)
	case ACCESS_ACCEPT:
		go radiusResHandler(rPayload, radius)
	case ACCESS_REJECT:
		go radiusResHandler(rPayload, radius)
	case ACCOUNTING_REQUEST:
		go radiusReqHandler(rPayload, radius)
	case ACCOUNTING_RESPONSE:
		go radiusResHandler(rPayload, radius)
	case ACCESS_CHALLENGE:
		go radiusResHandler(rPayload, radius)
	default:
		return
	}

}

// The request handler function does the request attribute sanitising
// and initialises a channel that is only shared between it and
// the resHandler, the resHandler knows about this channel based on its
// packet identifier and rPayload.ipPortHash
func radiusReqHandler(rPayload *radiusPayload, r *RADIUS) {
	r.transaction[rPayload.ipPortHash] = pktIdChan{pktId: rPayload.identifier, response: make(chan int)}
	fmt.Println("XXX req transaction", r.transaction)
}

// The resHandler makes use of the channel initialised by the reqHandler
// and sends a "ping" on the channel to let the reqHandler know that there
// is a response from the RADIUS server for the request. The connection is
// said to be closed when resHandler sends a "ping" to the reqHandler
func radiusResHandler(rPayload *radiusPayload, r *RADIUS) {
	if _, ok := r.transaction[rPayload.ipPortHash]; ok {
		fmt.Println("XXX res transaction", r.transaction)
	}
}

// This function takes in the captured RADIUS packet and shoves
// it into a radiusPayload struct and returns its address
func sanitiseRadius(pkt *protos.Packet) (rPayload *radiusPayload, err error) {
	payload := &radiusPayload{}
	payload.code = pkt.Payload[0]
	payload.identifier = pkt.Payload[1]
	payload.length = binary.BigEndian.Uint16(pkt.Payload[2:4])
	copy(payload.authenticator[:], pkt.Payload[4:21])

	// RFC 2865., Section 3., Length states that the minimum number
	// of bytes in a RADIUS payload is 20 and max is 4096
	if 20 > payload.length {
		return nil, errors.New("Payload minimum size not met")
	}

	if 4096 < payload.length {
		return nil, errors.New("Payload max size not met")
	}

	if 20 > len(pkt.Payload) {
		payload.attributes = pkt.Payload[21:]
	}

	switch payload.code {
	case ACCESS_REQUEST:
		payload.ipPortHash = pkt.Tuple.Hashable()
	case ACCESS_ACCEPT:
		payload.ipPortHash = pkt.Tuple.RevHashable()
	case ACCESS_REJECT:
		payload.ipPortHash = pkt.Tuple.RevHashable()
	case ACCOUNTING_REQUEST:
		payload.ipPortHash = pkt.Tuple.Hashable()
	case ACCOUNTING_RESPONSE:
		payload.ipPortHash = pkt.Tuple.RevHashable()
	case ACCESS_CHALLENGE:
		payload.ipPortHash = pkt.Tuple.Hashable()
	}

	return payload, nil
}
