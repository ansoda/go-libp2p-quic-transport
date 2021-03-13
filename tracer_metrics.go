package libp2pquic

import (
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/logging"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	activeConns     *prometheus.GaugeVec
	sentPackets     *prometheus.CounterVec
	rcvdPackets     *prometheus.CounterVec
	bufferedPackets *prometheus.CounterVec
	droppedPackets  *prometheus.CounterVec
	lostPackets     *prometheus.CounterVec
	connErrors      *prometheus.CounterVec
	// connDuration *prometheus.HistogramVec
)

func init() {
	const (
		direction = "direction"
		encLevel  = "encryption_level"
	)

	activeConns = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "quic_active_connections",
			Help: "QUIC connections handled",
		},
		[]string{direction},
	)
	prometheus.MustRegister(activeConns)
	sentPackets = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "quic_sent_packets",
			Help: "QUIC packets sent",
		},
		[]string{encLevel},
	)
	prometheus.MustRegister(sentPackets)
	rcvdPackets = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "quic_rcvd_packets",
			Help: "QUIC packets received",
		},
		[]string{encLevel},
	)
	prometheus.MustRegister(rcvdPackets)
	bufferedPackets = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "quic_buffered_packets",
			Help: "Buffered packets",
		},
		[]string{"packet_type"},
	)
	prometheus.MustRegister(bufferedPackets)
	droppedPackets = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "quic_dropped_packets",
			Help: "Dropped packets",
		},
		[]string{"packet_type", "reason"},
	)
	prometheus.MustRegister(droppedPackets)
	connErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "quic_conn_errors",
			Help: "QUIC connection errors",
		},
		[]string{"side", "error_code"},
	)
	prometheus.MustRegister(connErrors)
	lostPackets = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "quic_lost_packets",
			Help: "QUIC lost received",
		},
		[]string{encLevel, "reason"},
	)
	prometheus.MustRegister(lostPackets)
	// var buckets []float64
	// for _, d := range []time.Duration{time.Second, 10*time.Second, time.Minute, 10*time.Second, time.Hour, 24*time.Hour, 7*24*time.Hour} {
	// 	buckets = append(buckets, d.Seconds())
	// }
	// connDuration = prometheus.NewHistogramVec(
	// 	prometheus.HistogramOpts{
	// 		Name: "quic_connection_duration",
	// 		Help: "duration of QUIC connections",
	// 		Buckets: buckets,
	// 	},
	// 	[]string{direction},
	// )
	// prometheus.MustRegister(connDuration)
}

type metricsTracer struct{}

func (m *metricsTracer) TracerForConnection(p logging.Perspective, _ logging.ConnectionID) logging.ConnectionTracer {
	return &metricsConnTracer{perspective: p}
}

func (m *metricsTracer) SentPacket(addr net.Addr, header *logging.Header, count logging.ByteCount, frames []logging.Frame) {
}

func (m *metricsTracer) DroppedPacket(addr net.Addr, packetType logging.PacketType, count logging.ByteCount, reason logging.PacketDropReason) {
}

type metricsConnTracer struct {
	perspective logging.Perspective
	startTime   time.Time
}

var _ logging.ConnectionTracer = &metricsConnTracer{}

func (m *metricsConnTracer) getDirection() string {
	if m.perspective == logging.PerspectiveClient {
		return "outgoing"
	}
	return "incoming"
}

func (m *metricsConnTracer) getEncLevel(packetType logging.PacketType) string {
	switch packetType {
	case logging.PacketType0RTT:
		return "0-RTT"
	case logging.PacketTypeInitial:
		return "Initial"
	case logging.PacketTypeHandshake:
		return "Handshake"
	case logging.PacketTypeRetry:
		return "Retry"
	case logging.PacketType1RTT:
		return "1-RTT"
	default:
		return "unknown"
	}
}

func (m *metricsConnTracer) StartedConnection(net.Addr, net.Addr, logging.VersionNumber, logging.ConnectionID, logging.ConnectionID) {
	m.startTime = time.Now()
	activeConns.WithLabelValues(m.getDirection()).Inc()
}

func (m *metricsConnTracer) ClosedConnection(r logging.CloseReason) {
	activeConns.WithLabelValues(m.getDirection()).Dec()
	if _, _, ok := r.ApplicationError(); ok {
		return
	}
	var desc string
	side := "local"
	if _, ok := r.StatelessReset(); ok {
		side = "remote"
		desc = "stateless_reset"
	}
	if timeout, ok := r.Timeout(); ok {
		switch timeout {
		case logging.TimeoutReasonHandshake:
			desc = "handshake_timeout"
		case logging.TimeoutReasonIdle:
			desc = "idle_timeout"
		default:
			desc = "unknown timeout"
		}
	}
	if code, remote, ok := r.TransportError(); ok {
		if code == 0xc { // ignore APPLICATION_ERROR
			return
		}
		if remote {
			side = "remote"
		}
		desc = code.String()
	}
	connErrors.WithLabelValues(side, desc).Inc()
}
func (m *metricsConnTracer) SentTransportParameters(parameters *logging.TransportParameters)     {}
func (m *metricsConnTracer) ReceivedTransportParameters(parameters *logging.TransportParameters) {}
func (m *metricsConnTracer) RestoredTransportParameters(parameters *logging.TransportParameters) {}
func (m *metricsConnTracer) SentPacket(hdr *logging.ExtendedHeader, _ logging.ByteCount, _ *logging.AckFrame, _ []logging.Frame) {
	sentPackets.WithLabelValues(m.getEncLevel(logging.PacketTypeFromHeader(&hdr.Header))).Inc()
}

func (m *metricsConnTracer) ReceivedVersionNegotiationPacket(*logging.Header, []logging.VersionNumber) {
	rcvdPackets.WithLabelValues("Version Negotiation").Inc()
}

func (m *metricsConnTracer) ReceivedRetry(*logging.Header) {
	rcvdPackets.WithLabelValues("Retry").Inc()
}

func (m *metricsConnTracer) ReceivedPacket(hdr *logging.ExtendedHeader, _ logging.ByteCount, _ []logging.Frame) {
	rcvdPackets.WithLabelValues(m.getEncLevel(logging.PacketTypeFromHeader(&hdr.Header))).Inc()
}

func (m *metricsConnTracer) BufferedPacket(packetType logging.PacketType) {
	bufferedPackets.WithLabelValues(m.getEncLevel(packetType)).Inc()
}

func (m *metricsConnTracer) DroppedPacket(packetType logging.PacketType, _ logging.ByteCount, r logging.PacketDropReason) {
	var reason string
	switch r {
	case logging.PacketDropKeyUnavailable:
		reason = "key_unavailable"
	case logging.PacketDropUnknownConnectionID:
		reason = "unknown_connection_id"
	case logging.PacketDropHeaderParseError:
		reason = "header_parse_error"
	case logging.PacketDropPayloadDecryptError:
		reason = "payload_decrypt_error"
	case logging.PacketDropProtocolViolation:
		reason = "protocol_violation"
	case logging.PacketDropDOSPrevention:
		reason = "dos_prevention"
	case logging.PacketDropUnsupportedVersion:
		reason = "unsupported_version"
	case logging.PacketDropUnexpectedPacket:
		reason = "unexpected_packet"
	case logging.PacketDropUnexpectedSourceConnectionID:
		reason = "unexpected_source_connection_id"
	case logging.PacketDropUnexpectedVersion:
		reason = "unexpected_version"
	case logging.PacketDropDuplicate:
		reason = "duplicate"
	default:
		reason = "unknown"
	}
	droppedPackets.WithLabelValues(m.getEncLevel(packetType), reason).Inc()
}

func (m *metricsConnTracer) UpdatedMetrics(rttStats *logging.RTTStats, cwnd, bytesInFlight logging.ByteCount, packetsInFlight int) {
}

func (m *metricsConnTracer) LostPacket(level logging.EncryptionLevel, _ logging.PacketNumber, r logging.PacketLossReason) {
	var reason string
	switch r {
	case logging.PacketLossReorderingThreshold:
		reason = "reordering_threshold"
	case logging.PacketLossTimeThreshold:
		reason = "time_threshold"
	default:
		reason = "unknown"
	}
	lostPackets.WithLabelValues(level.String(), reason).Inc()
}

func (m *metricsConnTracer) UpdatedCongestionState(state logging.CongestionState) {}
func (m *metricsConnTracer) UpdatedPTOCount(value uint32)                         {}
func (m *metricsConnTracer) UpdatedKeyFromTLS(level logging.EncryptionLevel, perspective logging.Perspective) {
}
func (m *metricsConnTracer) UpdatedKey(generation logging.KeyPhase, remote bool)  {}
func (m *metricsConnTracer) DroppedEncryptionLevel(level logging.EncryptionLevel) {}
func (m *metricsConnTracer) DroppedKey(generation logging.KeyPhase)               {}
func (m *metricsConnTracer) SetLossTimer(timerType logging.TimerType, level logging.EncryptionLevel, time time.Time) {
}

func (m *metricsConnTracer) LossTimerExpired(timerType logging.TimerType, level logging.EncryptionLevel) {
}
func (m *metricsConnTracer) LossTimerCanceled() {}

func (m *metricsConnTracer) Close()                 {}
func (m *metricsConnTracer) Debug(name, msg string) {}
