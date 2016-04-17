package radius

import (
	"github.com/elastic/beats/libbeat/logp"

	"github.com/elastic/beats/packetbeat/procs"
	"github.com/elastic/beats/packetbeat/protos"
)

// Gateway function to analysing the protocol. This function does the following
// 1. Decodes and performs sanity checking on the received payload
// 2. Delegates control to an appropriate Type handler
func (radius *RADIUS) ParseUdp(pkt *protos.Packet) {

	logp.Debug("radius", "Parsing packet addressed with %s of length %d.",
		pkt.Tuple.String(), len(pkt.Payload))

	//XXX Process error
	rPayload, _ := decodeRadius(pkt)
	radiusTuple := RadiusTupleFromIpPort(&pkt.Tuple, TransportUdp, rPayload.identifier)

	radiusMsg := &RadiusMessage{
		Ts:           pkt.Ts,
		Tuple:        pkt.Tuple,
		CmdlineTuple: procs.ProcWatcher.FindProcessesTuple(&pkt.Tuple),
		Data:         rPayload,
		Length:       len(pkt.Payload),
	}

	switch rPayload.code {
	case ACCESS_REQUEST:
		radius.receivedRadiusRequest(&radiusTuple, radiusMsg)
	case ACCESS_ACCEPT:
		radius.receivedRadiusResponse(&radiusTuple, radiusMsg)
	case ACCESS_REJECT:
		radius.receivedRadiusResponse(&radiusTuple, radiusMsg)
	case ACCOUNTING_REQUEST:
		radius.receivedRadiusRequest(&radiusTuple, radiusMsg)
	case ACCOUNTING_RESPONSE:
		radius.receivedRadiusResponse(&radiusTuple, radiusMsg)
	case ACCESS_CHALLENGE:
		radius.receivedRadiusResponse(&radiusTuple, radiusMsg)
	}

}
