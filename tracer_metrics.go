package libp2pquic

import (
	"net"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/logging"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	activeConns     *prometheus.GaugeVec
	newConns        *prometheus.CounterVec
	closedConns     *prometheus.CounterVec
	sentPackets     *prometheus.CounterVec
	rcvdPackets     *prometheus.CounterVec
	bufferedPackets *prometheus.CounterVec
	droppedPackets  *prometheus.CounterVec
	lostPackets     *prometheus.CounterVec
	connErrors      *prometheus.CounterVec
	// connDuration *prometheus.HistogramVec
)

type aggregatingCollector struct {
	mutex sync.Mutex
	conns map[string] /* conn ID */ *metricsConnTracer
}

func newAggregatingCollector() *aggregatingCollector {
	return &aggregatingCollector{conns: make(map[string]*metricsConnTracer)}
}

var _ prometheus.Collector = &aggregatingCollector{}

func (c *aggregatingCollector) newRTTHistogram() prometheus.Summary {
	return prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "quic_smoothed_rtt",
		Help:    "Smoothed RTT",
		Buckets: []float64{0.001, 0.005, 0.01, 0.015, 0.02, 0.03, 0.05, 0.1, 0.15, 0.2, 0.3, 0.5, 0.75, 1, 1.5, 2, 5},
	})
}

func (c *aggregatingCollector) newConnectionDurationHistogram() prometheus.Summary {
	return prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "quic_connection_duration",
		Help:    "Connection Duration",
		Buckets: []float64{1, 5, 10, 30, 60, 10 * 60, 30 * 60, 3600, 3 * 3600, 12 * 3600, 24 * 3600, 7 * 24 * 3600, 31 * 24 * 3600},
	})
}

func (c *aggregatingCollector) Describe(descs chan<- *prometheus.Desc) {
	descs <- c.newRTTHistogram().Desc()
	descs <- c.newConnectionDurationHistogram().Desc()
}

func (c *aggregatingCollector) Collect(metrics chan<- prometheus.Metric) {
	now := time.Now()
	rtts := c.newRTTHistogram()
	connDurations := c.newConnectionDurationHistogram()
	c.mutex.Lock()
	for _, conn := range c.conns {
		if rtt, valid := conn.getSmoothedRTT(); valid {
			rtts.Observe(rtt.Seconds())
		}
		connDurations.Observe(now.Sub(conn.startTime).Seconds())
	}
	c.mutex.Unlock()
	metrics <- rtts
	metrics <- connDurations
}

func (c *aggregatingCollector) AddConn(id string, t *metricsConnTracer) {
	c.mutex.Lock()
	c.conns[id] = t
	c.mutex.Unlock()
}

func (c *aggregatingCollector) RemoveConn(id string) {
	c.mutex.Lock()
	delete(c.conns, id)
	c.mutex.Unlock()
}

var collector *aggregatingCollector

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
	closedConns = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "quic_closed_connections",
			Help: "closed QUIC connection",
		},
		[]string{direction},
	)
	prometheus.MustRegister(closedConns)
	newConns = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "quic_new_connections",
			Help: "new QUIC connection",
		},
		[]string{direction, "handshake_successful"},
	)
	prometheus.MustRegister(newConns)
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
	collector = newAggregatingCollector()
	prometheus.MustRegister(collector)
}

type metricsTracer struct{}

func (m *metricsTracer) TracerForConnection(p logging.Perspective, connID logging.ConnectionID) logging.ConnectionTracer {
	return &metricsConnTracer{perspective: p, connID: connID}
}

func (m *metricsTracer) SentPacket(addr net.Addr, header *logging.Header, count logging.ByteCount, frames []logging.Frame) {
}

func (m *metricsTracer) DroppedPacket(addr net.Addr, packetType logging.PacketType, count logging.ByteCount, reason logging.PacketDropReason) {
}

type metricsConnTracer struct {
	perspective       logging.Perspective
	startTime         time.Time
	connID            logging.ConnectionID
	handshakeComplete bool

	mutex              sync.Mutex
	numRTTMeasurements int
	rtt                time.Duration
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
	collector.AddConn(m.connID.String(), m)
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
	m.mutex.Lock()
	m.rtt = rttStats.SmoothedRTT()
	m.numRTTMeasurements++
	m.mutex.Unlock()
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
func (m *metricsConnTracer) UpdatedKey(generation logging.KeyPhase, remote bool) {}
func (m *metricsConnTracer) DroppedEncryptionLevel(level logging.EncryptionLevel) {
	if level == logging.EncryptionHandshake {
		m.handleHandshakeComplete()
	}
}
func (m *metricsConnTracer) DroppedKey(generation logging.KeyPhase) {}
func (m *metricsConnTracer) SetLossTimer(timerType logging.TimerType, level logging.EncryptionLevel, time time.Time) {
}

func (m *metricsConnTracer) LossTimerExpired(timerType logging.TimerType, level logging.EncryptionLevel) {
}
func (m *metricsConnTracer) LossTimerCanceled() {}

func (m *metricsConnTracer) Close() {
	if m.handshakeComplete {
		closedConns.WithLabelValues(m.getDirection()).Inc()
	} else {
		newConns.WithLabelValues(m.getDirection(), "false").Inc()
	}
	collector.RemoveConn(m.connID.String())
}

func (m *metricsConnTracer) Debug(name, msg string) {}

func (m *metricsConnTracer) handleHandshakeComplete() {
	m.handshakeComplete = true
	newConns.WithLabelValues(m.getDirection(), "true").Inc()
}

func (m *metricsConnTracer) getSmoothedRTT() (rtt time.Duration, valid bool) {
	m.mutex.Lock()
	rtt = m.rtt
	valid = m.numRTTMeasurements > 10
	m.mutex.Unlock()
	return
}
