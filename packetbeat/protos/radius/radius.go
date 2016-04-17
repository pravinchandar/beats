package radius

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/packetbeat/protos"
	"github.com/elastic/beats/packetbeat/publish"
	"github.com/urso/ucfg"
	"net"
	"time"
)

const MaxRadiusTupleRawSize = 16 + 16 + 2 + 2 + 4 + 1

type HashableRadiusTuple [MaxRadiusTupleRawSize]byte

type Transport uint8

const (
	TransportTcp = iota
	TransportUdp
)

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
	transactionTimeout time.Duration
	results            publish.Transactions
	Send_request       bool
	Send_response      bool

	transactions *common.Cache
}

// The captured RADIUS payload
type radiusPayload struct {
	code          uint8
	identifier    uint8
	length        uint16
	authenticator [16]byte
	attributes    []byte
}

type RadiusTuple struct {
	Ip_length          int
	Src_ip, Dst_ip     net.IP
	Src_port, Dst_port uint16
	Transport          Transport
	Id                 uint8 // radius pkt identifier

	raw    HashableRadiusTuple // Src_ip:Src_port:Dst_ip:Dst_port:Transport:Id
	revRaw HashableRadiusTuple // Dst_ip:Dst_port:Src_ip:Src_port:Transport:Id
}

type RadiusMessage struct {
	Ts           time.Time          // Time when the message was received.
	Tuple        common.IpPortTuple // Source and destination addresses of packet.
	CmdlineTuple *common.CmdlineTuple
	Data         *radiusPayload
	Length       int
}

type RadiusTransaction struct {
	ts           time.Time   // Time when the request was received.
	tuple        RadiusTuple // Key used to track this transaction in the transactionsMap.
	ResponseTime int32       // Elapsed time in milliseconds between the request and response.
	Src          common.Endpoint
	Dst          common.Endpoint
	Transport    Transport
	Notes        []string

	Request  *RadiusMessage
	Response *RadiusMessage
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

func (radius *RADIUS) ConnectionTimeout() time.Duration {
	return radius.transactionTimeout
}

func (t *RadiusTuple) String() string {
	return fmt.Sprintf("RadiusTuple src[%s:%d] dst[%s:%d] transport[%s] id[%d]",
		t.Src_ip.String(),
		t.Src_port,
		t.Dst_ip.String(),
		t.Dst_port,
		t.Transport,
		t.Id)
}

func (t RadiusTuple) Reverse() RadiusTuple {
	return RadiusTuple{
		Ip_length: t.Ip_length,
		Src_ip:    t.Dst_ip,
		Dst_ip:    t.Src_ip,
		Src_port:  t.Dst_port,
		Dst_port:  t.Src_port,
		Transport: t.Transport,
		Id:        t.Id,
		raw:       t.revRaw,
		revRaw:    t.raw,
	}
}

func (t *RadiusTuple) ComputeHashebles() {
	copy(t.raw[0:16], t.Src_ip)
	copy(t.raw[16:18], []byte{byte(t.Src_port >> 8), byte(t.Src_port)})
	copy(t.raw[18:34], t.Dst_ip)
	copy(t.raw[34:36], []byte{byte(t.Dst_port >> 8), byte(t.Dst_port)})
	copy(t.raw[36:37], []byte{byte(t.Id >> 8), byte(t.Id)})
	t.raw[38] = byte(t.Transport)

	copy(t.revRaw[0:16], t.Dst_ip)
	copy(t.revRaw[16:18], []byte{byte(t.Dst_port >> 8), byte(t.Dst_port)})
	copy(t.revRaw[18:34], t.Src_ip)
	copy(t.revRaw[34:36], []byte{byte(t.Src_port >> 8), byte(t.Src_port)})
	copy(t.revRaw[36:37], []byte{byte(t.Id >> 8), byte(t.Id)})
	t.revRaw[38] = byte(t.Transport)
}

func (radius *RADIUS) init(results publish.Transactions, config *radiusConfig) error {
	var removalListener = func(k common.Key, v common.Value) {
		trans, ok := v.(*RadiusTransaction)
		if !ok {
			logp.Err("Expired value is not a *RadiusTransaction.")
			return
		}
		radius.expireTransaction(trans)
	}

	radius.setFromConfig(config)
	radius.transactions = common.NewCacheWithRemovalListener(
		radius.transactionTimeout,
		protos.DefaultTransactionHashSize,
		removalListener)
	radius.transactions.StartJanitor(radius.transactionTimeout)

	radius.results = results

	return nil
}

func (radius *RADIUS) setFromConfig(config *radiusConfig) error {
	radius.Ports = config.Ports
	radius.Send_request = config.SendRequest
	radius.Send_response = config.SendResponse
	radius.transactionTimeout = time.Duration(config.TransactionTimeout) * time.Second
	return nil
}

func (radius *RADIUS) expireTransaction(t *RadiusTransaction) {
	t.Notes = append(t.Notes, NoResponse.Error())
	logp.Debug("radius", "%s %s", NoResponse.Error(), t.tuple.String())
	radius.publishTransaction(t)
}

// Hashable returns a hashable value that uniquely identifies
// the radius tuple.
func (t *RadiusTuple) Hashable() HashableRadiusTuple {
	return t.raw
}

// Hashable returns a hashable value that uniquely identifies
// the radius tuple after swapping the source and destination.
func (t *RadiusTuple) RevHashable() HashableRadiusTuple {
	return t.revRaw
}

// getTransaction returns the transaction associated with the given
// HashableRadiusTuple. The lookup key should be the HashableRadiusTuple associated
// with the request (src is the requestor). Nil is returned if the entry
// does not exist.
func (radius *RADIUS) getTransaction(k HashableRadiusTuple) *RadiusTransaction {
	v := radius.transactions.Get(k)
	if v != nil {
		return v.(*RadiusTransaction)
	}
	return nil
}

func (radius *RADIUS) receivedRadiusRequest(tuple *RadiusTuple, msg *RadiusMessage) {
	logp.Debug("radius", "Processing query. %s", tuple.String())

	trans := radius.deleteTransaction(tuple.Hashable())
	if trans != nil {
		// This happens if a client puts multiple requests in flight
		// with the same ID.
		trans.Notes = append(trans.Notes, DuplicateQueryMsg.Error())
		logp.Debug("radius", "%s %s", DuplicateQueryMsg.Error(), tuple.String())
		radius.publishTransaction(trans)
		radius.deleteTransaction(trans.tuple.Hashable())
	}

	trans = newTransaction(msg.Ts, *tuple, *msg.CmdlineTuple)
	radius.transactions.Put(tuple.Hashable(), trans)
	trans.Request = msg
}

func (radius *RADIUS) receivedRadiusResponse(tuple *RadiusTuple, msg *RadiusMessage) {
	logp.Debug("radius", "Processing response. %s", tuple.String())

	trans := radius.getTransaction(tuple.RevHashable())
	if trans == nil {
		trans = newTransaction(msg.Ts, tuple.Reverse(), common.CmdlineTuple{
			Src: msg.CmdlineTuple.Dst, Dst: msg.CmdlineTuple.Src})
		trans.Notes = append(trans.Notes, OrphanedResponse.Error())
		logp.Debug("radius", "%s %s", OrphanedResponse.Error(), tuple.String())
	}

	trans.Response = msg
	radius.publishTransaction(trans)
	radius.deleteTransaction(trans.tuple.Hashable())
}

// deleteTransaction deletes an entry from the transaction map and returns
// the deleted element. If the key does not exist then nil is returned.
func (radius *RADIUS) deleteTransaction(k HashableRadiusTuple) *RadiusTransaction {
	v := radius.transactions.Delete(k)
	if v != nil {
		return v.(*RadiusTransaction)
	}
	return nil
}

func newTransaction(ts time.Time, tuple RadiusTuple, cmd common.CmdlineTuple) *RadiusTransaction {
	trans := &RadiusTransaction{
		Transport: tuple.Transport,
		ts:        ts,
		tuple:     tuple,
	}
	trans.Src = common.Endpoint{
		Ip:   tuple.Src_ip.String(),
		Port: tuple.Src_port,
		Proc: string(cmd.Src),
	}
	trans.Dst = common.Endpoint{
		Ip:   tuple.Dst_ip.String(),
		Port: tuple.Dst_port,
		Proc: string(cmd.Dst),
	}
	return trans
}

func (radius *RADIUS) publishTransaction(t *RadiusTransaction) {
	if radius.results == nil {
		return
	}
	logp.Debug("radius", "Publishing transaction. %s", t.tuple.String())
}

// This function takes in the captured RADIUS packet and shoves
// it into a radiusPayload struct and returns its address
func decodeRadius(pkt *protos.Packet) (rPayload *radiusPayload, err error) {
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

	return payload, nil
}

func RadiusTupleFromIpPort(t *common.IpPortTuple, trans Transport, id uint8) RadiusTuple {
	tuple := RadiusTuple{
		Ip_length: t.Ip_length,
		Src_ip:    t.Src_ip,
		Dst_ip:    t.Dst_ip,
		Src_port:  t.Src_port,
		Dst_port:  t.Dst_port,
		Transport: trans,
		Id:        id,
	}
	tuple.ComputeHashebles()

	return tuple
}
